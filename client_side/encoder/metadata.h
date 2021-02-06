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
    int* filters_parameters_registry;
    int total_filters_parameters;
    double* filters_parameters;
    // Custody Info
    int total_digests;
    char** digests;
    // Frame Tag
    int frame_id;
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

void extend_json_w_fmt(char** json, char* fmt, void* data, int data_format)
{
    // data_format: 0: str; 1: int; 2: double
    char element[JSON_MAX_ELEM_LEN] = {0};
    switch (data_format)
    {
    case 0:
        snprintf(element, JSON_MAX_ELEM_LEN, fmt, data);
        break;
    case 1:
        snprintf(element, JSON_MAX_ELEM_LEN, fmt, *(int*)data);
        break;
    case 2:
        snprintf(element, JSON_MAX_ELEM_LEN, fmt, *(double*)data);
    default:
        break;
    }
    // if (is_int)
    //     snprintf(element, JSON_MAX_ELEM_LEN, fmt, *(int*)data);
    // else
    //     snprintf(element, JSON_MAX_ELEM_LEN, fmt, data);
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
    extend_json_wo_fmt(&json, "], \"filters_parameters_registry\": [");
    for (int i = 0; i < md->total_filters; i++) {
        if (i == 0)
            extend_json_w_fmt(&json, "\"%i\"", &(md->filters_parameters_registry[i]), 1);
        else
            extend_json_w_fmt(&json, ", \"%i\"", &(md->filters_parameters_registry[i]), 1);
    }
    
    extend_json_w_fmt(&json, "], \"total_filters_parameters\": %i, ",  &md->total_filters_parameters, 1);
    extend_json_wo_fmt(&json, "\"filters_parameters\": [");
    for (int i = 0; i < md->total_filters_parameters; i++) {
        if (i == 0)
            extend_json_w_fmt(&json, "\"%f\"", &(md->filters_parameters[i]), 2);
        else
            extend_json_w_fmt(&json, ", \"%f\"", &(md->filters_parameters[i]), 2);
    }
    extend_json_w_fmt(&json, "], \"total_digests\": %i, ",  &md->total_digests, 1);
    extend_json_wo_fmt(&json, "\"digests\": [");
   for (int i = 0; i < md->total_digests; i++) {
        if (i == 0)
            extend_json_w_fmt(&json, "\"%s\"", md->digests[i], 0);
        else
            extend_json_w_fmt(&json, ", \"%s\"", md->digests[i], 0);
    }
    extend_json_w_fmt(&json, "], \"frame_id\": %3i}\0",  &md->frame_id, 1);
    return json;
}

char* metadata_2_json_without_frame_id(metadata *md)
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
    extend_json_wo_fmt(&json, "], \"filters_parameters_registry\": [");
    for (int i = 0; i < md->total_filters; i++) {
        if (i == 0)
            extend_json_w_fmt(&json, "\"%i\"", &(md->filters_parameters_registry[i]), 1);
        else
            extend_json_w_fmt(&json, ", \"%i\"", &(md->filters_parameters_registry[i]), 1);
    }
    
    extend_json_w_fmt(&json, "], \"total_filters_parameters\": %i, ",  &md->total_filters_parameters, 1);
    extend_json_wo_fmt(&json, "\"filters_parameters\": [");
    for (int i = 0; i < md->total_filters_parameters; i++) {
        if (i == 0)
            extend_json_w_fmt(&json, "\"%f\"", &(md->filters_parameters[i]), 2);
        else
            extend_json_w_fmt(&json, ", \"%f\"", &(md->filters_parameters[i]), 2);
    }
    extend_json_w_fmt(&json, "], \"total_digests\": %i, ",  &md->total_digests, 1);
    extend_json_wo_fmt(&json, "\"digests\": [");
    for (int i = 0; i < md->total_digests; i++) {
        if (i == 0)
            extend_json_w_fmt(&json, "\"%s\"", md->digests[i], 0);
        else
            extend_json_w_fmt(&json, ", \"%s\"", md->digests[i], 0);
    }
    extend_json_wo_fmt(&json, "]}\0");
    return json;
}

metadata* json_2_metadata(char* json, size_t json_len)
{
    metadata* md = (metadata*)malloc(sizeof(metadata));
    jsmn_parser p;
    jsmntok_t t[128];
    jsmn_init(&p);
    int res = jsmn_parse(&p, json, json_len, t, 128);
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
            char* temp_timestamp_char_array = get_token_data(t[i+1], json);
            md->timestamp = atoi(temp_timestamp_char_array);
            free(temp_timestamp_char_array);
            i++;
        }
        else if (jsoneq(json, &t[i], "width") == 0)
        {
            char* temp_width_char_array = get_token_data(t[i+1], json);
            md->width = atoi(temp_width_char_array);
            free(temp_width_char_array);
            i++;
        }
        else if (jsoneq(json, &t[i], "height") == 0)
        {
            char* temp_height_char_array = get_token_data(t[i+1], json);
            md->height = atoi(temp_height_char_array);
            free(temp_height_char_array);
            i++;
        }
        else if (jsoneq(json, &t[i], "segment_id") == 0)
        {
            char* temp_segment_id_char_array = get_token_data(t[i+1], json);
            md->segment_id = atoi(temp_segment_id_char_array);
            free(temp_segment_id_char_array);
            i++;
        }
        else if (jsoneq(json, &t[i], "total_segments") == 0)
        {
            char* temp_total_segments_char_array = get_token_data(t[i+1], json);
            md->total_segments = atoi(temp_total_segments_char_array);
            free(temp_total_segments_char_array);
            i++;
        }
        else if (jsoneq(json, &t[i], "frame_rate") == 0)
        {
            char* temp_frame_rate_char_array = get_token_data(t[i+1], json);
            md->frame_rate = atoi(temp_frame_rate_char_array);
            free(temp_frame_rate_char_array);
            i++;
        }
        else if (jsoneq(json, &t[i], "total_frames") == 0)
        {
            char* temp_total_frames_char_array = get_token_data(t[i+1], json);
            md->total_frames = atoi(temp_total_frames_char_array);
            free(temp_total_frames_char_array);
            i++;
        }
        else if (jsoneq(json, &t[i], "total_filters") == 0)
        {
            char* temp_total_frames_char_array = get_token_data(t[i+1], json);
            md->total_filters = atoi(temp_total_frames_char_array);
            free(temp_total_frames_char_array);
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
        else if (jsoneq(json, &t[i], "filters_parameters_registry") == 0)
        {
            md->filters_parameters_registry = (int*)malloc(sizeof(int) * md->total_filters);
            if (t[i+1].type != JSMN_ARRAY)
                continue;
            char* temp_filters_parameters_registry_single;
            for (int j = 0; j < t[i+1].size; j++) {
                temp_filters_parameters_registry_single = get_token_data(t[i+j+2], json);
                md->filters_parameters_registry[j] = atoi(temp_filters_parameters_registry_single);
                free(temp_filters_parameters_registry_single);
            }
            i += t[i+1].size + 1;
        }
        else if (jsoneq(json, &t[i], "total_filters_parameters") == 0)
        {
            char* temp_total_filters_parameters = get_token_data(t[i+1], json);
            md->total_filters_parameters = atoi(temp_total_filters_parameters);
            free(temp_total_filters_parameters);
            i++;
        }
        else if (jsoneq(json, &t[i], "filters_parameters_registry") == 0)
        {
            md->filters_parameters = (double*)malloc(sizeof(double) * md->total_filters_parameters);
            if (t[i+1].type != JSMN_ARRAY)
                continue;
            char* temp_filter_parameter;
            for (int j = 0; j < t[i+1].size; j++) {
                temp_filter_parameter = get_token_data(t[i+j+2], json);
                md->filters_parameters[j] = atof(temp_filter_parameter);
                free(temp_filter_parameter);
            }
            i += t[i+1].size + 1;
        }
        else if (jsoneq(json, &t[i], "total_digests") == 0)
        {
            char* temp_total_digests_char_array = get_token_data(t[i+1], json);
            md->total_digests = atoi(temp_total_digests_char_array);
            free(temp_total_digests_char_array);
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
        else if (jsoneq(json, &t[i], "frame_id") == 0)
        {
            char* temp_frame_id_char_array = get_token_data(t[i+1], json);
            md->frame_id = atoi(temp_frame_id_char_array);
            free(temp_frame_id_char_array);
            i++;
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
    printf("filters_parameters_registry:\n");
    for (int i = 0; i < md->total_filters; i++) {
        printf("    filter %i: %i\n", i, md->filters_parameters_registry[i]);
    }
    printf("total_filters_parameters:  %i\n", md->total_filters_parameters);
    printf("filters_parameters:\n");
    for (int i = 0; i < md->total_filters_parameters; i++) {
        printf("    filter_parameter %i: %f\n", i, md->filters_parameters[i]);
    }
    printf("total_digests:  %i\n", md->total_digests);
    printf("digests:\n");
    for (int i = 0; i < md->total_digests; i++) {
        printf("    digest %i: %s\n", i, md->digests[i]);
    }
    printf("frame_id:  %i\n", md->frame_id);
}

void free_metadata(metadata* md){
    if(md->video_id){
        free(md->video_id);
    }
    if(md->filters){
        for(int i = 0; i < md->total_filters; ++i){
            free(md->filters[i]);
        }
        free(md->filters);
    }
    if(md->filters_parameters_registry){
        free(md->filters_parameters_registry);
    }
    if(md->filters_parameters){
        free(md->filters_parameters);
    }
    if(md->digests){
        for(int i = 0; i < md->total_digests; ++i){
            free(md->digests[i]);
        }
        free(md->digests);
    }
    free(md);
}

#ifdef __cplusplus
}
#endif

#endif /* METADATA_H */