#ifndef METADATA_H
#define METADATA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "string.h"
#include "jsmn.h"
#include "stdlib.h"
#include "stdio.h"
#include "time.h"

#define JSON_MAX_ELEM_LEN 100

typedef struct metadata {
    // Video Info
    char* video_id;
    time_t timestamp;
    int width;
    int height;
    // Segment Info
    int segment_id;
    int total_segments;
    int frame_rate;
    int total_frames;
    // Filter Info
    int total_filters;
    char** filters;
    // Custody Info
    int total_digests;
    char** digests;
} metadata;

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

char* get_token_data(jsmntok_t t, char* json)
{
    if (!json)
    {
        printf("get_token_data: json is NULL\n");
        return NULL;
    }
    int data_size = t.end - t.start + 1;
    char *data = (char*)malloc(data_size);
    memset(data, '\0', data_size);
    memcpy(data, json + t.start, (size_t)(data_size-1));
    return data;
}

void extend_json_wo_fmt(char** json, char* data)
{
    size_t p = strlen(*json);
    size_t data_len = strlen(data) + 1;
    *json = (char*)realloc(*json, p + data_len);
    memset(*json + p, 0, data_len);
    memcpy(*json + p, data, data_len - 1);
}

void extend_json_w_fmt(char** json, char* fmt, void* data, int is_int)
{
    char element[JSON_MAX_ELEM_LEN] = {0};
    if (is_int)
        snprintf(element, JSON_MAX_ELEM_LEN, fmt, *(int*)data);
    else
        snprintf(element, JSON_MAX_ELEM_LEN, fmt, data);
    size_t p = strlen(*json);
    size_t elem_len = strlen(element) + 1;
    char* tmp = NULL;
    tmp = (char*)realloc(*json, p + elem_len);
    if (tmp) {
        *json = tmp;
        memset(*json + p, 0, elem_len);
        memcpy(*json + p, element, elem_len - 1);
    } else {
        printf("Error reallocating memory\n");
    }
}

char* metadata_2_json(metadata *md)
{
    char* tmp = "{";
    char* json = (char*)malloc(strlen(tmp) + 1);
    memset(json, 0, strlen(tmp) + 1);
    memcpy(json, tmp, strlen(tmp));
    extend_json_w_fmt(&json, "\"video_id\": \"%s\", ",   md->video_id, 0);
    extend_json_w_fmt(&json, "\"timestamp\": %li, ",     &md->timestamp, 1);
    extend_json_w_fmt(&json, "\"width\": %i, ",          &md->width, 1);
    extend_json_w_fmt(&json, "\"height\": %i, ",         &md->height, 1);
    extend_json_w_fmt(&json, "\"segment_id\": %i, ",     &md->segment_id, 1);
    extend_json_w_fmt(&json, "\"total_segments\": %i, ", &md->total_segments, 1);
    extend_json_w_fmt(&json, "\"frame_rate\": %i, ",     &md->frame_rate, 1);
    extend_json_w_fmt(&json, "\"total_frames\": %i, ",   &md->total_frames, 1);
    extend_json_w_fmt(&json, "\"total_filters\": %i, ",  &md->total_filters, 1);
    extend_json_wo_fmt(&json, "\"filters\": [");
    for (int i = 0; i < md->total_filters; i++) {
        if (i == 0)
            extend_json_w_fmt(&json, "\"%s\"", md->filters[i], 0);
        else
            extend_json_w_fmt(&json, ", \"%s\"", md->filters[i], 0);
    }
    extend_json_w_fmt(&json, "], \"total_digests\": %i, ",  &md->total_digests, 1);
    extend_json_wo_fmt(&json, "\"digests\": [");
   for (int i = 0; i < md->total_digests; i++) {
        if (i == 0)
            extend_json_w_fmt(&json, "\"%s\"", md->digests[i], 0);
        else
            extend_json_w_fmt(&json, ", \"%s\"", md->digests[i], 0);
    }
    extend_json_wo_fmt(&json, "]}");
    return json;
}

metadata* json_2_metadata(char* json)
{
    metadata* md = (metadata*)malloc(sizeof(metadata));
    jsmn_parser p;
    jsmntok_t t[128];
    jsmn_init(&p);
    int res = jsmn_parse(&p, json, strlen(json), t, 128);
    if (res < 0) {
        printf("Error when parsing JSON: %s\n", json);
        return NULL;
    }
    for (int i = 1; i < res; i++) {
        if (jsoneq(json, &t[i], "video_id") == 0)
        {
            md->video_id = get_token_data(t[i+1], json);
            i++;
        }
        else if (jsoneq(json, &t[i], "timestamp") == 0)
        {
            md->timestamp = atoi(get_token_data(t[i+1], json));
            i++;
        }
        else if (jsoneq(json, &t[i], "width") == 0)
        {
            md->width = atoi(get_token_data(t[i+1], json));
            i++;
        }
        else if (jsoneq(json, &t[i], "height") == 0)
        {
            md->height = atoi(get_token_data(t[i+1], json));
            i++;
        }
        else if (jsoneq(json, &t[i], "segment_id") == 0)
        {
            md->segment_id = atoi(get_token_data(t[i+1], json));
            i++;
        }
        else if (jsoneq(json, &t[i], "total_segments") == 0)
        {
            md->total_segments = atoi(get_token_data(t[i+1], json));
            i++;
        }
        else if (jsoneq(json, &t[i], "frame_rate") == 0)
        {
            md->frame_rate = atoi(get_token_data(t[i+1], json));
            i++;
        }
        else if (jsoneq(json, &t[i], "total_frames") == 0)
        {
            md->total_frames = atoi(get_token_data(t[i+1], json));
            i++;
        }
        else if (jsoneq(json, &t[i], "total_filters") == 0)
        {
            md->total_filters = atoi(get_token_data(t[i+1], json));
            i++;
        }
        else if (jsoneq(json, &t[i], "filters") == 0)
        {
            md->filters = (char**)malloc(sizeof(char*) * md->total_filters);
            if (t[i+1].type != JSMN_ARRAY)
                continue;
            for (int j = 0; j < t[i+1].size; j++) {
                md->filters[j] = get_token_data(t[i+j+2], json);
            }
            i += t[i+1].size + 1;
        }
        else if (jsoneq(json, &t[i], "total_digests") == 0)
        {
            md->total_digests = atoi(get_token_data(t[i+1], json));
            i++;
        }
        else if (jsoneq(json, &t[i], "digests") == 0)
        {
            md->digests = (char**)malloc(sizeof(char*) * md->total_digests);
            if (t[i+1].type != JSMN_ARRAY)
                continue;
            for (int j = 0; j < t[i+1].size; j++) {
                md->digests[j] = get_token_data(t[i+j+2], json);
            }
            i += t[i+1].size + 1;
        }
        else
        {
            printf("Unexpected key: %.*s\n", t[i].end - t[i].start, json + t[i].start);
            break;
        }
    }
    return md;
}

void print_metadata(metadata* md) {
    if (!md) {
        printf("Metadata is NULL\n");
        return;
    }
    printf("video_id:       %s\n", md->video_id);
    printf("timestamp:      %li\n",md->timestamp);
    printf("width:          %i\n", md->width);
    printf("height:         %i\n", md->height);
    printf("segment_id:     %i\n", md->segment_id);
    printf("total_segments: %i\n", md->total_segments);
    printf("frame_rate:     %i\n", md->frame_rate);
    printf("total_frames:   %i\n", md->total_frames);
    printf("total_filters:  %i\n", md->total_filters);
    printf("filters:\n");
    for (int i = 0; i < md->total_filters; i++) {
        printf("    filter %i: %s\n", i, md->filters[i]);
    }
    printf("total_digests:  %i\n", md->total_digests);
    printf("digests:\n");
    for (int i = 0; i < md->total_digests; i++) {
        printf("    digest %i: %s\n", i, md->digests[i]);
    }
}

#ifdef __cplusplus
}
#endif

#endif /* METADATA_H */