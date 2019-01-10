#define DEBUG_WOLFSSL

#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"

#include "nvs_flash.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include <sys/socket.h>
#include <netdb.h>
#include "lwip/apps/sntp.h"

#include "esp8266/eagle_soc.h"
#include "driver/gpio.h"

#include "wolfssl/ssl.h"

EventGroupHandle_t wifi_event_group;

extern const uint8_t ca_crt_start[] asm("_binary_ca_crt_start");
extern const uint8_t ca_crt_end[] asm("_binary_ca_crt_end");

extern const uint8_t auth_dat_start[] asm("_binary_auth_dat_start");
extern const uint8_t auth_dat_end[] asm("_binary_auth_dat_end");

xQueueHandle gpio_queue = NULL;
SemaphoreHandle_t write_lock;

uint8_t read_buf[1024];
uint8_t pkt_buf[256];
uint8_t pkt_type;
uint8_t pkt_len;
uint8_t pkt_ptr;
uint8_t pkt_state;

uint8_t send_buf_all[260];
uint8_t *send_buf = send_buf_all + 4;

uint8_t connected = 0;

uint32_t last_inp = 0;
uint32_t last_send_inp = 0;

static const char *TAG = "home-client";

WOLFSSL *ssl = NULL;

uint32_t gpio_input_get();

esp_err_t wifi_event_handler(void *c, system_event_t *e) {
	switch(e->event_id) {
		case SYSTEM_EVENT_STA_START:
			ESP_ERROR_CHECK(tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA, CONFIG_DHCP_HOSTNAME));
			esp_wifi_connect();
			break;
		case SYSTEM_EVENT_STA_GOT_IP:
			xEventGroupSetBits(wifi_event_group, BIT0);
			break;
		case SYSTEM_EVENT_STA_DISCONNECTED:
			esp_wifi_connect();
			xEventGroupClearBits(wifi_event_group, BIT0);
			break;
		default:
			break;
	}
	return ESP_OK;
}

void wifi_init(void) {
	tcpip_adapter_init();
	wifi_event_group = xEventGroupCreate();
	ESP_ERROR_CHECK(esp_event_loop_init(wifi_event_handler, NULL));
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	wifi_event_group = xEventGroupCreate();
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	wifi_config_t wifi_cfg = {
		.sta = {
			.ssid = CONFIG_WIFI_SSID,
			.password = CONFIG_WIFI_PASSWORD,
		}
	};
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
	ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_cfg));
	ESP_ERROR_CHECK(esp_wifi_start());
}

void enable_sntp() {
	sntp_setoperatingmode(0);
	sntp_setservername(0, CONFIG_SNTP_HOST);
	sntp_init();
}

int send_pkt(uint8_t type, uint8_t len) {
	send_buf_all[0] = type;
	send_buf_all[1] = len;
	int ret = wolfSSL_write(ssl, send_buf_all, (uint32_t) len + 4);
	if(ret <= 0) {
		ESP_LOGE(TAG, "wolfSSL_write failed: %d", ret);
		return -1;
	}
	return 0;
}

int recv_pkt() {
	uint8_t send_type, send_len;
	uint8_t send = 0;

	switch(pkt_type) {
		case 0: // ping
			memcpy(send_buf, pkt_buf, pkt_len);
			send_type = 0;
			send_len = pkt_len;
			send = 1;
			break;
		case 1: // GPIO config
			if(pkt_len < 8)
				return 0;
			gpio_config_t cfg = {
				.pin_bit_mask = *(uint32_t *) pkt_buf,
				.mode = pkt_buf[4],
				.pull_up_en = pkt_buf[5],
				.pull_down_en = pkt_buf[6],
				.intr_type = pkt_buf[7],
			};
			ESP_ERROR_CHECK(gpio_config(&cfg));
			break;
		case 2: // GPIO get
			*(uint32_t *) send_buf = gpio_input_get();
			send_type = 2;
			send_len = 4;
			send = 1;
			break;
		case 3: // GPIO set
			if(pkt_len < 2)
				return 0;
			ESP_ERROR_CHECK(gpio_set_level(pkt_buf[0], pkt_buf[1]));
			break;
		case 255: // System reset
			esp_restart();
			break;
	}
	if(send)
		return send_pkt(send_type, send_len);
	return 0;
}

void IRAM_ATTR gpio_isr(void *arg) {
	uint32_t gpio_status = GPIO_REG_READ(GPIO_STATUS_ADDRESS);
	GPIO_REG_WRITE(GPIO_STATUS_W1TC_ADDRESS, gpio_status);

	uint32_t inp = gpio_input_get();
	if(last_inp != inp) {
		xQueueOverwriteFromISR(gpio_queue, &inp, NULL);
		last_inp = inp;
	}
}

void gpio_task(void *arg) {
	ESP_LOGI(TAG, "gpio_task started");
	while(1) {
		uint32_t inp;
		if(xQueueReceive(gpio_queue, &inp, portMAX_DELAY)) {
			if(last_send_inp != inp && connected) {
				xSemaphoreTake(write_lock, portMAX_DELAY);
				*(uint32_t *) send_buf = inp;
				send_pkt(2, 4);
				xSemaphoreGive(write_lock);
				last_send_inp = inp;
			}
		}
	}
}

void ssl_client(void *arg) {

	WOLFSSL_CTX *ctx = NULL;

	struct hostent *host;
	struct sockaddr_in sock_addr = {0};
	int sock;

	int ret;

	enable_sntp();

	while(1) {

		ESP_LOGI(TAG, "Resolving hostname: %s", CONFIG_HOST_ADDR);
		host = gethostbyname(CONFIG_HOST_ADDR);
		while(host == NULL) {
			ESP_LOGW(TAG, "Resolving hostname failed, retrying");
			vTaskDelay(100 / portTICK_RATE_MS);
			host = gethostbyname(CONFIG_HOST_ADDR);
		}

		ESP_LOGI(TAG, "wolfSSL_Init");
		ret = wolfSSL_Init();
		if(ret != WOLFSSL_SUCCESS) {
			ESP_LOGE(TAG, "wolfSSL_Init failed: %d", ret);
			goto f_cleanup;
		}

		ESP_LOGI(TAG, "wolfSSL_CTX_new");
		ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
		if(!ctx) {
			ESP_LOGE(TAG, "wolfSSL_CTX_new failed");
			goto f_cleanup;
		}

		ESP_LOGI(TAG, "socket");
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if(sock < 0) {
			ESP_LOGE(TAG, "socket failed");
			goto f_ctx_free;
		}

		ESP_LOGI(TAG, "wolfSSL_CTX_load_verify_buffer");
		ret = wolfSSL_CTX_load_verify_buffer(ctx, ca_crt_start, ca_crt_end - ca_crt_start, WOLFSSL_FILETYPE_PEM);
		if(ret != WOLFSSL_SUCCESS) {
			ESP_LOGE(TAG, "wolfSSL_CTX_load_verify_buffer failed: %d", ret);
			goto f_close;
		}
		
		ESP_LOGI(TAG, "wolfSSL_CTX_set_verify");
		wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

		sock_addr.sin_family = AF_INET;
		sock_addr.sin_port = htons(CONFIG_HOST_PORT);
		sock_addr.sin_addr.s_addr = ((struct in_addr *) host->h_addr)->s_addr;

		ESP_LOGI(TAG, "connect");
		ret = connect(sock, (struct sockaddr *) &sock_addr, sizeof(sock_addr));
		if(ret) {
			ESP_LOGE(TAG, "connect failed: %d", ret);
			goto f_close;
		}

		ESP_LOGI(TAG, "wolfSSL_new");
		ssl = wolfSSL_new(ctx);
		if(!ssl) {
			ESP_LOGE(TAG, "wolfSSL_new failed");
			goto f_close;
		}

		wolfSSL_check_domain_name(ssl, "server");

		wolfSSL_set_fd(ssl, sock);

		ESP_LOGI(TAG, "wolfSSL_connect");
		ret = wolfSSL_connect(ssl);
		if(ret != WOLFSSL_SUCCESS) {
			ESP_LOGE(TAG, "wolfSSL_connect failed: %d", wolfSSL_get_error(ssl, ret));
			goto f_free;
		}

		ESP_LOGI(TAG, "Connected");

		ret = wolfSSL_write(ssl, auth_dat_start, auth_dat_end - auth_dat_start);
		if(ret <= 0) {
			ESP_LOGE(TAG, "wolfSSL_write: %d", ret);
			goto f_shutdown;
		}

		connected = 1;

		while(1) {
			ret = wolfSSL_read(ssl, read_buf, sizeof(read_buf));
			if(ret <= 0) {
				ESP_LOGE(TAG, "wolfSSL_read: %d", ret);
				goto f_shutdown;
			}

			for(uint32_t i = 0; i < ret; ++i) {
				uint8_t c = read_buf[i];
				switch(pkt_state) {
					case 0:
						pkt_type = c;
						pkt_state = 1;
						break;
					case 1:
						pkt_len = c;
						pkt_state = 2;
						break;
					case 2:
						pkt_state = 3;
						break;
					case 3:
						if(pkt_len == 0) {
							xSemaphoreTake(write_lock, portMAX_DELAY);
							int ret = recv_pkt();
							xSemaphoreGive(write_lock);
							if(ret == -1)
								goto f_shutdown;
							pkt_state = 0;
						} else {
							pkt_ptr = 0;
							pkt_state = 4;
						}
						break;
					case 4:
						pkt_buf[pkt_ptr++] = c;
						if(pkt_ptr == pkt_len) {
							xSemaphoreTake(write_lock, portMAX_DELAY);
							int ret = recv_pkt();
							xSemaphoreGive(write_lock);
							if(ret == -1)
								goto f_shutdown;
							pkt_state = 0;
						}
						break;
					default:
						pkt_state = 0;
				}
			}
		}

f_shutdown:
		connected = 0;
		wolfSSL_shutdown(ssl);
f_free:
		connected = 0;
		wolfSSL_free(ssl);
f_close:
		connected = 0;
		close(sock);
f_ctx_free:
		connected = 0;
		wolfSSL_CTX_free(ctx);
f_cleanup:
		connected = 0;
		wolfSSL_Cleanup();
		
		vTaskDelay(CONFIG_RETRY_TIMEOUT / portTICK_RATE_MS);
	}
}

void app_main(void) {
	ESP_ERROR_CHECK(nvs_flash_init());
	struct timeval tv;
	tv.tv_sec = CONFIG_INITIAL_TIME;
	tv.tv_usec = 0;
	settimeofday(&tv, NULL);
	wifi_init();
	xTaskCreate(ssl_client, "ssl_client", 8192, NULL, 4, NULL);

	gpio_queue = xQueueCreate(1, sizeof(uint32_t));
	xTaskCreate(gpio_task, "gpio_task", 2048, NULL, 10, NULL);

	write_lock = xSemaphoreCreateMutex();

	portENTER_CRITICAL();
	_xt_isr_attach(ETS_GPIO_INUM, (_xt_isr) gpio_isr, NULL);
	_xt_isr_unmask(1 << ETS_GPIO_INUM);
	portEXIT_CRITICAL();
}
