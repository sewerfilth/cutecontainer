/*
 * wrap.c — Universal Content Description for .cute containers
 *
 * Manages typed wrapper metadata: serialization, composition,
 * variant tracking, and asset references.
 */

#include "cutecontainer/wrap.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── LE helpers ── */

static void w_put32(uint8_t *p, uint32_t v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static uint32_t w_get32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}

/* ── Type names ── */

const char *cc_wrap_type_name(cc_wrap_type type)
{
    switch (type) {
    case CC_WRAP_IMAGE:     return "image";
    case CC_WRAP_SPECTRAL:  return "spectral";
    case CC_WRAP_AUDIO:     return "audio";
    case CC_WRAP_VIDEO:     return "video";
    case CC_WRAP_SCENE:     return "scene";
    case CC_WRAP_GEOMETRY:  return "geometry";
    case CC_WRAP_MATERIAL:  return "material";
    case CC_WRAP_DOCUMENT:  return "document";
    case CC_WRAP_MODEL:     return "model";
    case CC_WRAP_FONT:      return "font";
    case CC_WRAP_ARCHIVE:   return "archive";
    case CC_WRAP_STREAM:    return "stream";
    case CC_WRAP_TIMELINE:  return "timeline";
    case CC_WRAP_LUT:       return "lut";
    case CC_WRAP_PROFILE:   return "profile";
    case CC_WRAP_TEXTURE:   return "texture";
    case CC_WRAP_SPRITE:    return "sprite";
    case CC_WRAP_SKELETON:  return "skeleton";
    case CC_WRAP_ANIMATION: return "animation";
    case CC_WRAP_TILEMAP:   return "tilemap";
    case CC_WRAP_PARTICLE:  return "particle";
    case CC_WRAP_SHADER:    return "shader";
    case CC_WRAP_LEVEL:     return "level";
    case CC_WRAP_PHYSICS:   return "physics";
    case CC_WRAP_NAVMESH:   return "navmesh";
    case CC_WRAP_DIALOGUE:  return "dialogue";
    case CC_WRAP_VOXEL:     return "voxel";
    case CC_WRAP_TERRAIN:   return "terrain";
    case CC_WRAP_PREFAB:    return "prefab";
    case CC_WRAP_EXR_EXT: return "exr-ext";
    case CC_WRAP_DPX:     return "dpx";
    case CC_WRAP_HDR:     return "hdr";
    case CC_WRAP_ACES:    return "aces";
    case CC_WRAP_SPREADSHEET: return "spreadsheet";
    case CC_WRAP_PRESENTATION: return "presentation";
    case CC_WRAP_RICHTEXT:  return "richtext";
    case CC_WRAP_FORM:      return "form";
    case CC_WRAP_DATABASE:  return "database";
    case CC_WRAP_CHART:     return "chart";
    case CC_WRAP_DIAGRAM:   return "diagram";
    case CC_WRAP_CALENDAR:  return "calendar";
    case CC_WRAP_CONTACTS:  return "contacts";
    case CC_WRAP_EMAIL:     return "email";
    case CC_WRAP_NOTEBOOK:  return "notebook";
    case CC_WRAP_VECTOR:    return "vector";
    case CC_WRAP_CUSTOM:    return "custom";
    default:                return "unknown";
    }
}

/* ── Init ── */

void cc_wrap_init(cc_wrap_set *ws)
{
    memset(ws, 0, sizeof(cc_wrap_set));
}

/* ── Add ── */

int cc_wrap_add(cc_wrap_set *ws, cc_wrap_type type, const void *data, size_t size)
{
    if (!ws || ws->count >= CC_MAX_WRAPS) return -1;

    /* allocate a copy of the data */
    void *copy = malloc(size);
    if (!copy) return -1;
    memcpy(copy, data, size);

    cc_wrap_entry *e = &ws->wraps[ws->count++];
    e->type = type;
    e->size = (uint32_t)size;
    e->data = copy;
    return 0;
}

int cc_wrap_add_variant(cc_wrap_set *ws, const cc_wrap_variant *v)
{
    if (!ws || ws->variant_count >= CC_MAX_VARIANTS) return -1;
    ws->variants[ws->variant_count++] = *v;
    return 0;
}

int cc_wrap_add_ref(cc_wrap_set *ws, const cc_wrap_ref *r)
{
    if (!ws || ws->ref_count >= CC_MAX_REFS) return -1;
    ws->refs[ws->ref_count++] = *r;
    return 0;
}

/* ── Find ── */

const void *cc_wrap_find(const cc_wrap_set *ws, cc_wrap_type type, size_t *size)
{
    if (!ws) return NULL;
    for (uint32_t i = 0; i < ws->count; i++) {
        if (ws->wraps[i].type == type) {
            if (size) *size = ws->wraps[i].size;
            return ws->wraps[i].data;
        }
    }
    return NULL;
}

/* ── Serialize ──
 *
 * Layout:
 *   [4] wrap_count
 *   [4] variant_count
 *   [4] ref_count
 *   [4] reserved
 *   For each wrap:
 *     [4] type
 *     [4] data_size
 *     [data_size] wrapper data
 *   For each variant:
 *     [sizeof(cc_wrap_variant)] variant struct
 *   For each ref:
 *     [sizeof(cc_wrap_ref)] ref struct
 */

int cc_wrap_serialize(const cc_wrap_set *ws, uint8_t **out, size_t *out_len)
{
    if (!ws || !out || !out_len) return -1;

    /* calculate total size */
    size_t total = 16;  /* header */
    for (uint32_t i = 0; i < ws->count; i++)
        total += 8 + ws->wraps[i].size;
    total += ws->variant_count * sizeof(cc_wrap_variant);
    total += ws->ref_count * sizeof(cc_wrap_ref);

    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    uint8_t *p = buf;

    /* header */
    w_put32(p, ws->count);          p += 4;
    w_put32(p, ws->variant_count);  p += 4;
    w_put32(p, ws->ref_count);      p += 4;
    w_put32(p, 0);                  p += 4;  /* reserved */

    /* wraps */
    for (uint32_t i = 0; i < ws->count; i++) {
        w_put32(p, (uint32_t)ws->wraps[i].type);  p += 4;
        w_put32(p, ws->wraps[i].size);             p += 4;
        memcpy(p, ws->wraps[i].data, ws->wraps[i].size);
        p += ws->wraps[i].size;
    }

    /* variants */
    for (uint32_t i = 0; i < ws->variant_count; i++) {
        memcpy(p, &ws->variants[i], sizeof(cc_wrap_variant));
        p += sizeof(cc_wrap_variant);
    }

    /* refs */
    for (uint32_t i = 0; i < ws->ref_count; i++) {
        memcpy(p, &ws->refs[i], sizeof(cc_wrap_ref));
        p += sizeof(cc_wrap_ref);
    }

    *out = buf;
    *out_len = total;
    return 0;
}

/* ── Deserialize ── */

int cc_wrap_deserialize(cc_wrap_set *ws, const uint8_t *data, size_t len)
{
    if (!ws || !data || len < 16) return -1;

    cc_wrap_init(ws);

    const uint8_t *p = data;
    uint32_t wc = w_get32(p); p += 4;
    uint32_t vc = w_get32(p); p += 4;
    uint32_t rc = w_get32(p); p += 4;
    p += 4;  /* reserved */

    if (wc > CC_MAX_WRAPS) wc = CC_MAX_WRAPS;
    if (vc > CC_MAX_VARIANTS) vc = CC_MAX_VARIANTS;
    if (rc > CC_MAX_REFS) rc = CC_MAX_REFS;

    for (uint32_t i = 0; i < wc; i++) {
        if ((size_t)(p - data) + 8 > len) break;
        uint32_t type = w_get32(p); p += 4;
        uint32_t sz   = w_get32(p); p += 4;
        if ((size_t)(p - data) + sz > len) break;

        cc_wrap_add(ws, (cc_wrap_type)type, p, sz);
        p += sz;
    }

    for (uint32_t i = 0; i < vc; i++) {
        if ((size_t)(p - data) + sizeof(cc_wrap_variant) > len) break;
        memcpy(&ws->variants[ws->variant_count++], p, sizeof(cc_wrap_variant));
        p += sizeof(cc_wrap_variant);
    }

    for (uint32_t i = 0; i < rc; i++) {
        if ((size_t)(p - data) + sizeof(cc_wrap_ref) > len) break;
        memcpy(&ws->refs[ws->ref_count++], p, sizeof(cc_wrap_ref));
        p += sizeof(cc_wrap_ref);
    }

    return 0;
}

/* ── Import / Export stubs ──
 * Full implementation would detect format by extension/magic and
 * call the appropriate codec. For now, these are the entry points. */

int cc_wrap_probe_file(const char *path, cc_wrap_set *ws)
{
    if (!path || !ws) return -1;
    cc_wrap_init(ws);

    /* detect by extension */
    const char *ext = strrchr(path, '.');
    if (!ext) return -1;

    /* standard raster images (8-bit sRGB) */
    if (strcmp(ext, ".png") == 0 || strcmp(ext, ".jpg") == 0 ||
        strcmp(ext, ".jpeg") == 0 || strcmp(ext, ".bmp") == 0 ||
        strcmp(ext, ".tga") == 0 || strcmp(ext, ".gif") == 0 ||
        strcmp(ext, ".webp") == 0 || strcmp(ext, ".ico") == 0 ||
        strcmp(ext, ".psd") == 0) {
        cc_wrap_image img = {0};
        img.color_space = CC_CS_SRGB;
        img.pixel_format = CC_PF_UINT8;
        img.channels = CC_CH_RGBA;
        img.num_channels = 4;
        img.pixel_aspect = 1.0f;
        cc_wrap_add(ws, CC_WRAP_IMAGE, &img, sizeof(img));
        return 0;
    }

    /* OpenEXR — half/float HDR, deep pixels, multi-part, AOVs */
    if (strcmp(ext, ".exr") == 0) {
        cc_wrap_image img = {0};
        img.pixel_format = CC_PF_FLOAT16;
        img.channels = CC_CH_RGBA;
        img.color_space = CC_CS_LINEAR_SRGB;
        img.num_channels = 4;
        img.pixel_aspect = 1.0f;
        img.compression = CC_IMG_COMP_ZIP;
        cc_wrap_add(ws, CC_WRAP_IMAGE, &img, sizeof(img));

        cc_wrap_exr_ext exr = {0};
        exr.view_count = 1;
        cc_wrap_add(ws, CC_WRAP_EXR_EXT, &exr, sizeof(exr));
        return 0;
    }

    /* TIFF — 8/16/32-bit, multi-page, geospatial */
    if (strcmp(ext, ".tiff") == 0 || strcmp(ext, ".tif") == 0) {
        cc_wrap_image img = {0};
        img.color_space = CC_CS_SRGB;
        img.pixel_format = CC_PF_UINT16;
        img.channels = CC_CH_RGBA;
        img.num_channels = 4;
        img.pixel_aspect = 1.0f;
        img.tiled = 1;
        cc_wrap_add(ws, CC_WRAP_IMAGE, &img, sizeof(img));
        return 0;
    }

    /* DPX — film scanning / recording */
    if (strcmp(ext, ".dpx") == 0 || strcmp(ext, ".cin") == 0) {
        cc_wrap_image img = {0};
        img.pixel_format = CC_PF_UINT10;
        img.channels = CC_CH_RGB;
        img.color_space = CC_CS_ARRI_LOGC;
        img.num_channels = 3;
        img.pixel_aspect = 1.0f;
        cc_wrap_add(ws, CC_WRAP_IMAGE, &img, sizeof(img));

        cc_wrap_dpx dpx = {0};
        dpx.film_gauge = 35.0f;
        cc_wrap_add(ws, CC_WRAP_DPX, &dpx, sizeof(dpx));
        return 0;
    }

    /* HDR radiance formats */
    if (strcmp(ext, ".hdr") == 0 || strcmp(ext, ".rgbe") == 0) {
        cc_wrap_image img = {0};
        img.pixel_format = CC_PF_FLOAT32;
        img.channels = CC_CH_RGB;
        img.color_space = CC_CS_LINEAR_SRGB;
        img.num_channels = 3;
        img.pixel_aspect = 1.0f;
        cc_wrap_add(ws, CC_WRAP_IMAGE, &img, sizeof(img));

        cc_wrap_hdr hdr = {0};
        hdr.type = CC_HDR_SDR;
        cc_wrap_add(ws, CC_WRAP_HDR, &hdr, sizeof(hdr));
        return 0;
    }

    if (strcmp(ext, ".wav") == 0 || strcmp(ext, ".flac") == 0 ||
        strcmp(ext, ".aac") == 0 || strcmp(ext, ".mp3") == 0) {
        cc_wrap_audio aud = {0};
        aud.sample_rate = 48000;
        aud.channels = 2;
        aud.bit_depth = 16;
        cc_wrap_add(ws, CC_WRAP_AUDIO, &aud, sizeof(aud));
        return 0;
    }

    if (strcmp(ext, ".mov") == 0 || strcmp(ext, ".mp4") == 0 ||
        strcmp(ext, ".mkv") == 0) {
        cc_wrap_video vid = {0};
        vid.color_space = CC_CS_REC709;
        cc_wrap_add(ws, CC_WRAP_VIDEO, &vid, sizeof(vid));
        return 0;
    }

    if (strcmp(ext, ".usd") == 0 || strcmp(ext, ".usda") == 0 ||
        strcmp(ext, ".usdc") == 0 || strcmp(ext, ".usdz") == 0 ||
        strcmp(ext, ".gltf") == 0 || strcmp(ext, ".glb") == 0 ||
        strcmp(ext, ".obj") == 0 || strcmp(ext, ".fbx") == 0) {
        cc_wrap_scene scn = {0};
        scn.up_axis = 1;  /* Z-up default */
        scn.meters_per_unit = 1.0f;
        scn.fps = 24.0f;
        cc_wrap_add(ws, CC_WRAP_SCENE, &scn, sizeof(scn));
        return 0;
    }

    if (strcmp(ext, ".onnx") == 0 || strcmp(ext, ".mlmodel") == 0 ||
        strcmp(ext, ".tflite") == 0 || strcmp(ext, ".pt") == 0) {
        cc_wrap_model mdl = {0};
        cc_wrap_add(ws, CC_WRAP_MODEL, &mdl, sizeof(mdl));
        return 0;
    }

    /* game dev formats */
    if (strcmp(ext, ".dds") == 0 || strcmp(ext, ".ktx") == 0 ||
        strcmp(ext, ".ktx2") == 0 || strcmp(ext, ".pvr") == 0 ||
        strcmp(ext, ".basis") == 0) {
        cc_wrap_texture tex = {0};
        tex.tex_type = CC_TEX_2D;
        tex.format = CC_TEXFMT_RGBA8;
        cc_wrap_add(ws, CC_WRAP_TEXTURE, &tex, sizeof(tex));
        return 0;
    }

    if (strcmp(ext, ".spv") == 0 || strcmp(ext, ".spirv") == 0) {
        cc_wrap_shader shd = {0};
        shd.language = CC_SHADER_LANG_SPIRV;
        cc_wrap_add(ws, CC_WRAP_SHADER, &shd, sizeof(shd));
        return 0;
    }

    if (strcmp(ext, ".metal") == 0) {
        cc_wrap_shader shd = {0};
        shd.language = CC_SHADER_LANG_MSL;
        cc_wrap_add(ws, CC_WRAP_SHADER, &shd, sizeof(shd));
        return 0;
    }

    if (strcmp(ext, ".hlsl") == 0) {
        cc_wrap_shader shd = {0};
        shd.language = CC_SHADER_LANG_HLSL;
        cc_wrap_add(ws, CC_WRAP_SHADER, &shd, sizeof(shd));
        return 0;
    }

    if (strcmp(ext, ".glsl") == 0 || strcmp(ext, ".vert") == 0 ||
        strcmp(ext, ".frag") == 0 || strcmp(ext, ".comp") == 0) {
        cc_wrap_shader shd = {0};
        shd.language = CC_SHADER_LANG_GLSL;
        cc_wrap_add(ws, CC_WRAP_SHADER, &shd, sizeof(shd));
        return 0;
    }

    if (strcmp(ext, ".wgsl") == 0) {
        cc_wrap_shader shd = {0};
        shd.language = CC_SHADER_LANG_WGSL;
        cc_wrap_add(ws, CC_WRAP_SHADER, &shd, sizeof(shd));
        return 0;
    }

    if (strcmp(ext, ".tmx") == 0 || strcmp(ext, ".tmj") == 0) {
        cc_wrap_tilemap tm = {0};
        cc_wrap_add(ws, CC_WRAP_TILEMAP, &tm, sizeof(tm));
        return 0;
    }

    if (strcmp(ext, ".vox") == 0) {
        cc_wrap_voxel vox = {0};
        cc_wrap_add(ws, CC_WRAP_VOXEL, &vox, sizeof(vox));
        return 0;
    }

    if (strcmp(ext, ".cube") == 0 || strcmp(ext, ".3dl") == 0) {
        cc_wrap_lut lut = {0};
        lut.type = 1;
        cc_wrap_add(ws, CC_WRAP_LUT, &lut, sizeof(lut));
        return 0;
    }

    /* office / productivity formats */
    if (strcmp(ext, ".xlsx") == 0 || strcmp(ext, ".xls") == 0 ||
        strcmp(ext, ".csv") == 0 || strcmp(ext, ".tsv") == 0 ||
        strcmp(ext, ".ods") == 0 || strcmp(ext, ".numbers") == 0) {
        cc_wrap_spreadsheet ss = {0};
        cc_wrap_add(ws, CC_WRAP_SPREADSHEET, &ss, sizeof(ss));
        return 0;
    }

    if (strcmp(ext, ".pptx") == 0 || strcmp(ext, ".ppt") == 0 ||
        strcmp(ext, ".odp") == 0 || strcmp(ext, ".key") == 0) {
        cc_wrap_presentation pres = {0};
        pres.aspect_ratio = 16.0f / 9.0f;
        cc_wrap_add(ws, CC_WRAP_PRESENTATION, &pres, sizeof(pres));
        return 0;
    }

    if (strcmp(ext, ".docx") == 0 || strcmp(ext, ".doc") == 0 ||
        strcmp(ext, ".odt") == 0 || strcmp(ext, ".rtf") == 0 ||
        strcmp(ext, ".pages") == 0) {
        cc_wrap_richtext rt = {0};
        cc_wrap_add(ws, CC_WRAP_RICHTEXT, &rt, sizeof(rt));
        return 0;
    }

    if (strcmp(ext, ".pdf") == 0) {
        cc_wrap_document doc = {0};
        doc.format = 3; /* PDF */
        cc_wrap_add(ws, CC_WRAP_DOCUMENT, &doc, sizeof(doc));
        return 0;
    }

    if (strcmp(ext, ".md") == 0 || strcmp(ext, ".txt") == 0) {
        cc_wrap_document doc = {0};
        doc.format = (strcmp(ext, ".md") == 0) ? 1 : 0;
        doc.encoding = 0; /* UTF-8 */
        cc_wrap_add(ws, CC_WRAP_DOCUMENT, &doc, sizeof(doc));
        return 0;
    }

    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) {
        cc_wrap_document doc = {0};
        doc.format = 2; /* HTML */
        cc_wrap_add(ws, CC_WRAP_DOCUMENT, &doc, sizeof(doc));
        return 0;
    }

    if (strcmp(ext, ".db") == 0 || strcmp(ext, ".sqlite") == 0 ||
        strcmp(ext, ".sqlite3") == 0) {
        cc_wrap_database db = {0};
        cc_wrap_add(ws, CC_WRAP_DATABASE, &db, sizeof(db));
        return 0;
    }

    if (strcmp(ext, ".ipynb") == 0) {
        cc_wrap_notebook nb = {0};
        memcpy(nb.kernel, "python3", 7);
        memcpy(nb.language, "python", 6);
        cc_wrap_add(ws, CC_WRAP_NOTEBOOK, &nb, sizeof(nb));
        return 0;
    }

    if (strcmp(ext, ".svg") == 0) {
        cc_wrap_vector vec = {0};
        cc_wrap_add(ws, CC_WRAP_VECTOR, &vec, sizeof(vec));
        return 0;
    }

    if (strcmp(ext, ".ics") == 0 || strcmp(ext, ".ical") == 0) {
        cc_wrap_calendar cal = {0};
        cc_wrap_add(ws, CC_WRAP_CALENDAR, &cal, sizeof(cal));
        return 0;
    }

    if (strcmp(ext, ".vcf") == 0 || strcmp(ext, ".vcard") == 0) {
        cc_wrap_contacts con = {0};
        cc_wrap_add(ws, CC_WRAP_CONTACTS, &con, sizeof(con));
        return 0;
    }

    if (strcmp(ext, ".eml") == 0 || strcmp(ext, ".msg") == 0) {
        cc_wrap_email em = {0};
        cc_wrap_add(ws, CC_WRAP_EMAIL, &em, sizeof(em));
        return 0;
    }

    if (strcmp(ext, ".ttf") == 0 || strcmp(ext, ".otf") == 0 ||
        strcmp(ext, ".woff") == 0 || strcmp(ext, ".woff2") == 0) {
        /* font — use the existing CC_WRAP_FONT type, no struct yet */
        cc_wrap_custom font = {0};
        memcpy(font.ext_type, "font", 4);
        cc_wrap_add(ws, CC_WRAP_FONT, &font, sizeof(font));
        return 0;
    }

    return -1;
}

int cc_wrap_import(const char *in_path, const char *out_path, int compress)
{
    (void)in_path; (void)out_path; (void)compress;
    /* TODO: implement format-specific import bridges */
    return -1;
}

int cc_wrap_export(const char *in_path, const char *out_path)
{
    (void)in_path; (void)out_path;
    /* TODO: implement format-specific export bridges */
    return -1;
}
