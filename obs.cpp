#include <obs-module.h>
#include <obs-frontend-api.h>
#include <util/platform.h>
#include <util/threading.h>
#include <util/bmem.h>
#include <util/dstr.h>

OBS_DECLARE_MODULE()

static const char *congestion_control_id = "congestion_control";

struct congestion_control_data {
    int bitrate;
    bool congestion_detected;
};

static void congestion_control_update(void *data, obs_data_t *settings)
{
    struct congestion_control_data *ccd = data;
    ccd->bitrate = (int)obs_data_get_int(settings, "bitrate");
}

static void *congestion_control_create(obs_data_t *settings, obs_source_t *source)
{
    struct congestion_control_data *ccd = bzalloc(sizeof(struct congestion_control_data));
    congestion_control_update(ccd, settings);
    return ccd;
}

static void congestion_control_destroy(void *data)
{
    struct congestion_control_data *ccd = data;
    bfree(ccd);
}

static obs_properties_t *congestion_control_properties(void *data)
{
    obs_properties_t *props = obs_properties_create();
    obs_properties_add_int(props, "bitrate", "Bitrate", 100, 10000, 100);
    return props;
}

static void congestion_control_tick(void *data, float seconds)
{
    struct congestion_control_data *ccd = data;
    // ここでeBPFからの情報を受け取り、輻輳状態を判断する
    // 輻輳が検出された場合はビットレートを下げる
    if (ccd->congestion_detected) {
        ccd->bitrate = ccd->bitrate * 0.8; // 20%減少
        obs_encoder_set_video_bitrate(obs_get_video_encoder(), ccd->bitrate);
    }
}

struct obs_source_info congestion_control = {
    .id = congestion_control_id,
    .type = OBS_SOURCE_TYPE_FILTER,
    .output_flags = OBS_SOURCE_VIDEO,
    .get_name = congestion_control_name,
    .create = congestion_control_create,
    .destroy = congestion_control_destroy,
    .update = congestion_control_update,
    .get_properties = congestion_control_properties,
    .video_tick = congestion_control_tick,
};

bool obs_module_load(void)
{
    obs_register_source(&congestion_control);
    return true;
}
