idf_component_register(SRCS "wifi.c" "http-req.c"
                    INCLUDE_DIRS "includes" REQUIRES esp_wifi nvs_flash)
