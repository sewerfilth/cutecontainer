/*
 * wrap.h — Universal Content Description for .cute containers
 *
 * Agnostic, structured wrappers that describe what's inside a container.
 * Inspired by USD composition but not limited to 3D — covers image,
 * audio, video, scene, model, document, and user-defined content.
 *
 * Key principles:
 *   - Each wrapper is a typed metadata schema (not raw bytes)
 *   - Wrappers compose: a container can have multiple overlapping wrappers
 *     (e.g., image + spectral + color profile on the same payload)
 *   - Asset references: wrappers can point to external .cute files
 *   - Variants: same content in multiple representations (HDR/SDR, hi/lo)
 *   - Import bridge: each wrapper type can convert from external formats
 *
 * On-disk layout (in container meta section):
 *   [4] wrap_count (uint32)
 *   For each wrapper:
 *     [4] wrap_type (uint32)
 *     [4] wrap_size (uint32, total bytes for this wrapper including header)
 *     [wrap_size - 8] wrapper-specific metadata
 */

#ifndef CUTECONTAINER_WRAP_H
#define CUTECONTAINER_WRAP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ──────────────────────────────────────────────────────────────
 * Wrapper types
 * ────────────────────────────────────────────────────────────── */

typedef enum {
    CC_WRAP_IMAGE     = 0x0001,  /* raster image */
    CC_WRAP_SPECTRAL  = 0x0002,  /* spectral image (film module) */
    CC_WRAP_AUDIO     = 0x0003,  /* audio data */
    CC_WRAP_VIDEO     = 0x0004,  /* video stream */
    CC_WRAP_SCENE     = 0x0005,  /* 3D scene graph */
    CC_WRAP_GEOMETRY  = 0x0006,  /* mesh / curve / point cloud */
    CC_WRAP_MATERIAL  = 0x0007,  /* surface material / shader */
    CC_WRAP_DOCUMENT  = 0x0008,  /* structured document */
    CC_WRAP_MODEL     = 0x0009,  /* ML model weights + graph */
    CC_WRAP_FONT      = 0x000A,  /* font data */
    CC_WRAP_ARCHIVE   = 0x000B,  /* file collection (depo ARCV) */
    CC_WRAP_STREAM    = 0x000C,  /* real-time data descriptor */
    CC_WRAP_TIMELINE  = 0x000D,  /* edit decision list / composition */
    CC_WRAP_LUT       = 0x000E,  /* color look-up table */
    CC_WRAP_PROFILE   = 0x000F,  /* color / device profile */

    /* ── Game development types ── */
    CC_WRAP_TEXTURE   = 0x0010,  /* GPU texture (mips, BC/ASTC, cubemap, array) */
    CC_WRAP_SPRITE    = 0x0011,  /* sprite sheet / atlas */
    CC_WRAP_SKELETON  = 0x0012,  /* bone hierarchy + bind pose */
    CC_WRAP_ANIMATION = 0x0013,  /* keyframe animation clips */
    CC_WRAP_TILEMAP   = 0x0014,  /* 2D tile map / grid */
    CC_WRAP_PARTICLE  = 0x0015,  /* particle system definition */
    CC_WRAP_SHADER    = 0x0016,  /* GPU shader (SPIRV, MSL, HLSL, GLSL, WGSL) */
    CC_WRAP_LEVEL     = 0x0017,  /* level / map / world layout */
    CC_WRAP_PHYSICS   = 0x0018,  /* collision shapes / rigid body config */
    CC_WRAP_NAVMESH   = 0x0019,  /* navigation mesh */
    CC_WRAP_DIALOGUE  = 0x001A,  /* dialogue tree / localized strings */
    CC_WRAP_VOXEL     = 0x001B,  /* voxel grid / volume data */
    CC_WRAP_TERRAIN   = 0x001C,  /* heightmap terrain + splat maps */
    CC_WRAP_PREFAB    = 0x001D,  /* entity prefab (component bundle) */

    /* ── VFX / film pipeline types ── */
    CC_WRAP_EXR_EXT   = 0x001E,  /* EXR deep / multi-view / AOV extension */
    CC_WRAP_DPX       = 0x001F,  /* DPX film scan metadata */
    CC_WRAP_HDR       = 0x0030,  /* HDR10 / Dolby Vision / HLG metadata */
    CC_WRAP_ACES      = 0x0031,  /* ACES color pipeline descriptor */

    /* ── Office / productivity types ── */
    CC_WRAP_SPREADSHEET = 0x0020, /* tabular data (sheets, cells, formulas) */
    CC_WRAP_PRESENTATION= 0x0021, /* slide deck */
    CC_WRAP_RICHTEXT    = 0x0022, /* styled text (RTF / word-processor) */
    CC_WRAP_FORM        = 0x0023, /* form fields + validation */
    CC_WRAP_DATABASE    = 0x0024, /* structured records / tables */
    CC_WRAP_CHART       = 0x0025, /* chart / graph definition */
    CC_WRAP_DIAGRAM     = 0x0026, /* vector diagram / flowchart */
    CC_WRAP_CALENDAR    = 0x0027, /* events / schedule (iCal-like) */
    CC_WRAP_CONTACTS    = 0x0028, /* address book / vCard-like */
    CC_WRAP_EMAIL       = 0x0029, /* email message (headers + body + attachments) */
    CC_WRAP_NOTEBOOK    = 0x002A, /* computational notebook (code + output cells) */
    CC_WRAP_VECTOR      = 0x002B, /* vector graphics (SVG-like paths + shapes) */

    CC_WRAP_CUSTOM    = 0xFF00,  /* user-defined (type in ext_type field) */
} cc_wrap_type;

/* ──────────────────────────────────────────────────────────────
 * Color spaces (shared across image, video, scene wrappers)
 * ────────────────────────────────────────────────────────────── */

typedef enum {
    CC_CS_LINEAR_SRGB  = 0,     /* linear sRGB (D65) — working space */
    CC_CS_SRGB         = 1,     /* sRGB with gamma */
    CC_CS_DCI_P3       = 2,     /* DCI-P3 (Display P3 D65) */
    CC_CS_REC709       = 3,     /* Rec. 709 (HDTV) */
    CC_CS_REC2020      = 4,     /* Rec. 2020 (UHDTV) */
    CC_CS_ACES_CG      = 5,     /* ACEScg (Academy linear) */
    CC_CS_ACES_CC      = 6,     /* ACEScc (log) */
    CC_CS_ARRI_LOGC    = 7,     /* ARRI LogC */
    CC_CS_RED_LOG3G10  = 8,     /* RED Log3G10 */
    CC_CS_SPECTRAL     = 9,     /* spectral (wavelength-sampled, no matrix) */
    CC_CS_XYZ          = 10,    /* CIE XYZ */
    CC_CS_RAW          = 0xFF,  /* unspecified / camera raw */
} cc_color_space;

/* ──────────────────────────────────────────────────────────────
 * Pixel / sample formats
 * ────────────────────────────────────────────────────────────── */

typedef enum {
    CC_PF_UINT8    = 0,
    CC_PF_UINT10   = 1,     /* 10-bit (DPX, ProRes) */
    CC_PF_UINT12   = 2,     /* 12-bit (cinema cameras) */
    CC_PF_UINT16   = 3,
    CC_PF_UINT32   = 4,
    CC_PF_FLOAT16  = 5,     /* half — EXR native, GPU textures */
    CC_PF_FLOAT32  = 6,     /* full float — EXR, HDR processing */
    CC_PF_FLOAT64  = 7,     /* double — scientific, accumulator */
} cc_pixel_format;

typedef enum {
    CC_CH_GRAY     = 1,
    CC_CH_GRAY_A   = 2,
    CC_CH_RGB      = 3,
    CC_CH_RGBA     = 4,
    CC_CH_YCBCR    = 5,     /* 4:2:2 or 4:4:4 */
    CC_CH_YCBCRA   = 6,     /* 4:4:4:4 with alpha */
    CC_CH_XYZ      = 7,     /* CIE XYZ tristimulus */
    CC_CH_SPECTRAL = 0xFE,  /* N bands (count in wrapper) */
    CC_CH_ARBITRARY= 0xFF,  /* named channels (EXR-style) */
} cc_channel_layout;

/* ── Compression methods (for image/EXR storage) ── */

typedef enum {
    CC_IMG_COMP_NONE   = 0,
    CC_IMG_COMP_RLE    = 1,
    CC_IMG_COMP_ZIP    = 2,     /* zlib (EXR ZIP) */
    CC_IMG_COMP_ZIPS   = 3,     /* zlib single-scanline (EXR ZIPS) */
    CC_IMG_COMP_PIZ    = 4,     /* wavelet (EXR PIZ) */
    CC_IMG_COMP_PXR24  = 5,     /* lossy 24-bit float (EXR PXR24) */
    CC_IMG_COMP_B44    = 6,     /* lossy 4x4 block (EXR B44) */
    CC_IMG_COMP_B44A   = 7,     /* B44 with flat-area optimization */
    CC_IMG_COMP_DWAA   = 8,     /* lossy DCT 32-scanline (EXR DWAA) */
    CC_IMG_COMP_DWAB   = 9,     /* lossy DCT 256-scanline (EXR DWAB) */
    CC_IMG_COMP_PRESS  = 10,    /* cutepress rANS+LZ */
} cc_image_compression;

/* ──────────────────────────────────────────────────────────────
 * Per-type wrapper metadata structs
 *
 * Each struct is serialized directly into the container meta
 * section after the (type, size) header.
 * ────────────────────────────────────────────────────────────── */

/* ── Image ── */

typedef struct {
    uint32_t             width;
    uint32_t             height;
    cc_pixel_format      pixel_format;
    cc_channel_layout    channels;
    cc_color_space       color_space;
    cc_image_compression compression;
    uint16_t             num_channels;    /* actual count (4 for RGBA, N for spectral/arbitrary) */
    uint16_t             mip_levels;      /* 0 or 1 = no mips */
    float                dpi;             /* 0 = unspecified */
    float                pixel_aspect;    /* pixel aspect ratio (1.0 = square, 2.0 = anamorphic) */
    float                exposure;        /* EXR: exposure value for display (0 = default) */
    float                white_luminance; /* cd/m² (EXR: whiteLuminance, 0 = unspec) */
    uint8_t              premultiplied;   /* alpha pre-multiplied */
    uint8_t              tiled;           /* 1 = tiled storage (EXR tiles) */
    uint8_t              deep;            /* 1 = deep pixel (EXR deep) */
    uint8_t              multipart;       /* 1 = multi-part file (EXR multi-part) */
    uint16_t             tile_width;      /* 0 = scanline */
    uint16_t             tile_height;
    uint16_t             part_count;      /* for multipart: number of parts */
    uint16_t             layer_count;     /* named layers (EXR: diffuse.R, spec.R, etc.) */
    uint32_t             data_window[4];  /* EXR: xMin, yMin, xMax, yMax (0 = full) */
    uint32_t             display_window[4]; /* EXR: display window (crop) */
} cc_wrap_image;

/* ── EXR deep / multi-view / AOV extension ──
 *
 * Compose with CC_WRAP_IMAGE for full EXR support.
 * Covers features beyond basic image: deep pixels,
 * arbitrary output variables (AOVs), stereo views,
 * and per-channel metadata.
 */

typedef enum {
    CC_DEEP_SCANLINE = 0,  /* deep scanline */
    CC_DEEP_TILED    = 1,  /* deep tiled */
} cc_deep_type;

typedef struct {
    /* deep pixel info */
    cc_deep_type    deep_type;
    uint64_t        max_samples;         /* max samples per pixel */
    uint64_t        total_samples;       /* total across all pixels */

    /* views (stereo / multi-view) */
    uint16_t        view_count;          /* 1=mono, 2=stereo, N=multi */
    uint8_t         default_view;        /* index of hero view */
    uint8_t         reserved;

    /* AOV / render pass channels */
    uint16_t        aov_count;           /* arbitrary output variables */
    /* followed by aov_count × cc_aov_channel descriptors */
} cc_wrap_exr_ext;

/* AOV channel descriptor (render passes: diffuse, specular, depth, normals, etc.) */
typedef struct {
    uint8_t         name[32];            /* e.g., "diffuse", "specular", "N", "Z", "crypto00" */
    cc_pixel_format format;              /* per-channel format (half, float, uint32) */
    uint16_t        num_components;      /* 1=scalar, 3=vector, 4=RGBA */
    uint16_t        reserved;
} cc_aov_channel;

/* ── DPX (Digital Picture Exchange) ──
 *
 * SMPTE 268M — motion picture film scanning / recording.
 * Compose with CC_WRAP_IMAGE for film pipeline metadata.
 */

typedef struct {
    uint32_t        dpx_version;         /* DPX header version */
    uint8_t         orientation;         /* 0=L→R T→B, see SMPTE 268M §6.1 */
    uint8_t         transfer;            /* transfer characteristic (log, linear, etc.) */
    uint8_t         colorimetric;        /* colorimetric spec */
    uint8_t         packing;             /* bit packing method */
    float           gamma;               /* applied gamma (0 = linear) */
    float           black_level;         /* code value for black */
    float           white_level;         /* code value for white */
    float           film_gauge;          /* mm (e.g., 35.0 for 35mm) */
    uint32_t        frame_number;
    uint32_t        sequence_length;
    uint8_t         timecode[12];        /* SMPTE timecode string */
    uint8_t         edge_code[16];       /* Keycode / film edge code */
} cc_wrap_dpx;

/* ── HDR metadata (HDR10 / Dolby Vision / HLG) ──
 *
 * Compose with CC_WRAP_IMAGE or CC_WRAP_VIDEO for HDR grading info.
 */

typedef enum {
    CC_HDR_SDR      = 0,
    CC_HDR_HDR10    = 1,    /* SMPTE ST 2084 PQ + ST 2086 metadata */
    CC_HDR_HDR10P   = 2,    /* HDR10+ (dynamic metadata) */
    CC_HDR_DOLBY    = 3,    /* Dolby Vision */
    CC_HDR_HLG      = 4,    /* Hybrid Log-Gamma (ARIB STD-B67) */
} cc_hdr_type;

typedef struct {
    cc_hdr_type     type;
    /* SMPTE ST 2086 mastering display */
    float           mastering_primaries[8]; /* Rx,Ry, Gx,Gy, Bx,By, Wx,Wy */
    float           max_luminance;          /* cd/m² (nits) of mastering display */
    float           min_luminance;
    /* CTA-861.3 MaxCLL / MaxFALL */
    float           max_cll;                /* maximum content light level */
    float           max_fall;               /* maximum frame-average light level */
    /* tone mapping hints */
    float           target_max_nits;        /* intended display peak */
    float           knee_point;             /* PQ knee for tone mapping */
} cc_wrap_hdr;

/* ── ACES metadata ──
 *
 * Academy Color Encoding System pipeline descriptor.
 * Compose with CC_WRAP_IMAGE or CC_WRAP_PROFILE.
 */

typedef enum {
    CC_ACES_ACES    = 0,    /* ACES2065-1 (AP0 linear, scene-referred) */
    CC_ACES_ACEScg  = 1,    /* ACEScg (AP1 linear, working space) */
    CC_ACES_ACEScc  = 2,    /* ACEScc (AP1 log, grading) */
    CC_ACES_ACEScct = 3,    /* ACEScct (AP1 log with toe, grading) */
    CC_ACES_ACESproxy= 4,   /* ACESproxy (integer encoding for transport) */
    CC_ACES_ADX     = 5,    /* Academy Density Exchange (film scan) */
} cc_aces_encoding;

typedef struct {
    cc_aces_encoding encoding;
    uint32_t         idt_id;          /* Input Device Transform ID (0 = none) */
    uint32_t         lmt_count;       /* Look Modification Transforms applied */
    uint32_t         odt_id;          /* Output Device Transform ID (0 = none) */
    uint32_t         rrt_version;     /* Reference Rendering Transform version */
    float            aces_version;    /* e.g., 1.3 */
    uint8_t          clip_name[32];
} cc_wrap_aces;

/* ── Spectral (extends image with wavelength info) ── */

typedef struct {
    uint32_t        width;
    uint32_t        height;
    uint16_t        num_bands;
    uint16_t        bits_per_band;  /* 16, 32, 64 */
    float           wavelength_min; /* nm */
    float           wavelength_max; /* nm */
    uint8_t         spectral_mode;  /* CF_SPECTRAL_128/256/512 */
    uint8_t         reserved[3];
} cc_wrap_spectral;

/* ── Audio ── */

typedef struct {
    uint32_t        sample_rate;    /* Hz */
    uint16_t        channels;
    uint16_t        bit_depth;
    cc_pixel_format sample_format;
    uint64_t        sample_count;
    uint64_t        duration_us;    /* microseconds */
    uint32_t        codec;          /* 0=PCM, 1=FLAC, 2=AAC, 3=Opus */
    uint8_t         reserved[4];
} cc_wrap_audio;

/* ── Video ── */

typedef struct {
    uint32_t        width;
    uint32_t        height;
    float           fps;
    uint64_t        frame_count;
    uint64_t        duration_us;
    uint32_t        codec;          /* 0=raw, 1=ProRes, 2=H265, 3=AV1 */
    uint32_t        prores_profile; /* if codec=ProRes: 0-5 profile */
    cc_color_space  color_space;
    cc_pixel_format pixel_format;
    uint16_t        bit_depth;
    uint8_t         interlaced;
    uint8_t         reserved;
} cc_wrap_video;

/* ── Scene (3D scene graph, USD-like) ── */

typedef struct {
    uint32_t        prim_count;     /* total primitives in hierarchy */
    uint32_t        mesh_count;
    uint32_t        camera_count;
    uint32_t        light_count;
    uint32_t        material_count;
    uint32_t        animation_count;
    uint8_t         up_axis;        /* 0=Y-up, 1=Z-up */
    uint8_t         handedness;     /* 0=right, 1=left */
    uint16_t        reserved;
    float           meters_per_unit;
    float           time_start;     /* animation time range */
    float           time_end;
    float           fps;
    uint32_t        variant_count;  /* number of variant sets */
    uint32_t        reference_count;/* external asset references */
} cc_wrap_scene;

/* ── Geometry (single mesh / curve / point cloud) ── */

typedef struct {
    uint32_t        vertex_count;
    uint32_t        face_count;     /* 0 for points/curves */
    uint32_t        index_count;
    uint8_t         topology;       /* 0=triangles, 1=quads, 2=polygon, 3=curves, 4=points */
    uint8_t         has_normals;
    uint8_t         has_uvs;
    uint8_t         has_colors;
    uint8_t         has_tangents;
    uint8_t         uv_sets;        /* number of UV sets */
    uint16_t        blend_shapes;   /* morph target count */
    float           bounds_min[3];  /* AABB */
    float           bounds_max[3];
} cc_wrap_geometry;

/* ── Material ── */

typedef struct {
    uint32_t        model;          /* 0=PBR metallic-rough, 1=PBR spec-gloss, 2=phong, 3=unlit, 4=spectral */
    uint16_t        texture_count;
    uint16_t        property_count;
    float           base_color[4];
    float           metallic;
    float           roughness;
    float           ior;
    float           transmission;
    float           emission_strength;
    uint8_t         double_sided;
    uint8_t         reserved[3];
} cc_wrap_material;

/* ── Document ── */

typedef struct {
    uint32_t        page_count;
    uint32_t        encoding;       /* 0=UTF-8, 1=UTF-16, 2=binary */
    uint32_t        format;         /* 0=plain, 1=markdown, 2=HTML, 3=PDF, 4=RTF */
    uint64_t        char_count;
    uint64_t        byte_count;
    uint8_t         language[8];    /* ISO 639-1 code (null-terminated) */
} cc_wrap_document;

/* ── ML Model ── */

typedef struct {
    uint32_t        framework;      /* 0=ONNX, 1=CoreML, 2=TFLite, 3=PyTorch, 4=custom */
    uint32_t        op_count;
    uint32_t        param_count_m;  /* millions of parameters */
    uint32_t        input_count;
    uint32_t        output_count;
    cc_pixel_format weight_format;
    uint32_t        quantization;   /* 0=none, 1=int8, 2=int4, 3=fp16 */
    uint8_t         name[32];       /* model name (null-terminated) */
} cc_wrap_model;

/* ── Timeline (edit decision list / composition) ── */

typedef struct {
    float           fps;
    float           duration;       /* seconds */
    uint32_t        track_count;
    uint32_t        clip_count;
    uint32_t        transition_count;
    uint32_t        marker_count;
    uint8_t         timecode_format; /* 0=SMPTE, 1=frames, 2=seconds */
    uint8_t         reserved[3];
} cc_wrap_timeline;

/* ── LUT (color look-up table) ── */

typedef struct {
    uint32_t        type;           /* 0=1D, 1=3D */
    uint32_t        size;           /* 1D: entries, 3D: cube_size^3 */
    uint16_t        input_channels;
    uint16_t        output_channels;
    cc_color_space  input_space;
    cc_color_space  output_space;
    cc_pixel_format precision;
    uint8_t         reserved[4];
} cc_wrap_lut;

/* ── Color / device profile ── */

typedef struct {
    cc_color_space  color_space;
    uint32_t        profile_type;   /* 0=ICC, 1=ACES, 2=custom */
    float           white_point[2]; /* CIE xy */
    float           primaries[6];   /* Rx,Ry, Gx,Gy, Bx,By */
    float           gamma;          /* 0 = use TRC */
    uint32_t        trc_size;       /* transfer curve entries (0 = gamma) */
} cc_wrap_profile;

/* ══════════════════════════════════════════════════════════════
 * Game development wrapper types
 * ══════════════════════════════════════════════════════════════ */

/* ── GPU Texture ── */

typedef enum {
    CC_TEX_2D        = 0,
    CC_TEX_3D        = 1,
    CC_TEX_CUBE      = 2,
    CC_TEX_2D_ARRAY  = 3,
    CC_TEX_CUBE_ARRAY= 4,
} cc_texture_type;

typedef enum {
    CC_TEXFMT_RGBA8      = 0,
    CC_TEXFMT_RGBA16F    = 1,
    CC_TEXFMT_RGBA32F    = 2,
    CC_TEXFMT_R8         = 3,
    CC_TEXFMT_RG8        = 4,
    CC_TEXFMT_R16F       = 5,
    CC_TEXFMT_R32F       = 6,
    CC_TEXFMT_BC1        = 10,  /* DXT1 */
    CC_TEXFMT_BC3        = 11,  /* DXT5 */
    CC_TEXFMT_BC5        = 12,  /* normal map */
    CC_TEXFMT_BC7        = 13,  /* high-quality */
    CC_TEXFMT_ASTC_4X4   = 20,
    CC_TEXFMT_ASTC_6X6   = 21,
    CC_TEXFMT_ASTC_8X8   = 22,
    CC_TEXFMT_ETC2       = 30,
} cc_texture_format;

typedef struct {
    uint32_t           width;
    uint32_t           height;
    uint32_t           depth;           /* 1 for 2D, >1 for 3D / array layers */
    cc_texture_type    tex_type;
    cc_texture_format  format;
    uint16_t           mip_levels;
    uint16_t           array_layers;    /* 6 for cubemap, N for arrays */
    cc_color_space     color_space;
    uint8_t            srgb;            /* 1 = sRGB decode on sample */
    uint8_t            generate_mips;   /* 1 = engine should gen mips */
    uint8_t            wrap_u;          /* 0=repeat, 1=clamp, 2=mirror */
    uint8_t            wrap_v;
    uint8_t            filter;          /* 0=nearest, 1=bilinear, 2=trilinear, 3=aniso */
    uint8_t            max_aniso;       /* anisotropic filter level */
    uint8_t            reserved[2];
} cc_wrap_texture;

/* ── Sprite sheet / Atlas ── */

typedef struct {
    uint32_t        atlas_width;
    uint32_t        atlas_height;
    uint32_t        sprite_count;
    uint32_t        default_fps;        /* for animated sprites */
    uint16_t        padding;            /* pixels between sprites */
    uint8_t         packed;             /* 0=grid, 1=packed (rects follow) */
    uint8_t         rotated;            /* 1 = sprites may be rotated 90° */
    /* if packed: sprite_count × { x, y, w, h, ox, oy, ow, oh } uint16 tuples follow */
} cc_wrap_sprite;

/* ── Skeleton (bone hierarchy) ── */

typedef struct {
    uint32_t        bone_count;
    uint32_t        root_index;
    uint8_t         coordinate_system;  /* 0=Y-up right, 1=Z-up right, 2=Y-up left */
    uint8_t         reserved[3];
    float           bind_scale;         /* global scale for bind pose */
    /* payload: bone_count × { parent_idx(u32), name(32), bind_pos(3f), bind_rot(4f), bind_scale(3f) } */
} cc_wrap_skeleton;

/* ── Animation clips ── */

typedef enum {
    CC_ANIM_TRANSFORM  = 0,     /* position/rotation/scale */
    CC_ANIM_SKELETAL   = 1,     /* bone keyframes */
    CC_ANIM_MORPH      = 2,     /* blend shape weights */
    CC_ANIM_PROPERTY   = 3,     /* arbitrary float property */
    CC_ANIM_SPRITE     = 4,     /* sprite frame sequence */
    CC_ANIM_EVENT      = 5,     /* trigger events at times */
} cc_anim_type;

typedef struct {
    cc_anim_type    anim_type;
    uint32_t        track_count;
    uint32_t        keyframe_count;
    float           duration;           /* seconds */
    float           fps;
    uint8_t         loop;               /* 0=once, 1=loop, 2=pingpong */
    uint8_t         interpolation;      /* 0=step, 1=linear, 2=cubic, 3=hermite */
    uint8_t         reserved[2];
    uint8_t         name[32];
} cc_wrap_animation;

/* ── Tile map ── */

typedef struct {
    uint32_t        map_width;          /* in tiles */
    uint32_t        map_height;
    uint32_t        tile_width;         /* pixels */
    uint32_t        tile_height;
    uint32_t        layer_count;
    uint32_t        tileset_count;
    uint32_t        object_count;       /* placed entities */
    uint8_t         orientation;        /* 0=orthogonal, 1=isometric, 2=hexagonal */
    uint8_t         render_order;       /* 0=right-down, 1=right-up, etc. */
    uint8_t         infinite;           /* 1 = chunked infinite map */
    uint8_t         reserved;
} cc_wrap_tilemap;

/* ── Particle system ── */

typedef struct {
    uint32_t        max_particles;
    float           lifetime_min;
    float           lifetime_max;
    float           emit_rate;          /* particles per second */
    uint8_t         emitter_shape;      /* 0=point, 1=sphere, 2=box, 3=cone, 4=edge */
    uint8_t         space;              /* 0=local, 1=world */
    uint8_t         blend_mode;         /* 0=alpha, 1=additive, 2=multiply */
    uint8_t         sort;               /* 0=none, 1=back-to-front, 2=by-age */
    float           gravity[3];
    uint16_t        texture_index;      /* ref to texture wrapper/asset */
    uint16_t        sprite_frames;      /* animated texture frames */
} cc_wrap_particle;

/* ── GPU Shader ── */

typedef enum {
    CC_SHADER_VERTEX   = 0,
    CC_SHADER_FRAGMENT = 1,
    CC_SHADER_COMPUTE  = 2,
    CC_SHADER_GEOMETRY = 3,
    CC_SHADER_TESS_CTRL = 4,
    CC_SHADER_TESS_EVAL = 5,
    CC_SHADER_MESH     = 6,
    CC_SHADER_TASK     = 7,
    CC_SHADER_RAY_GEN  = 8,
    CC_SHADER_RAY_MISS = 9,
    CC_SHADER_RAY_HIT  = 10,
} cc_shader_stage;

typedef enum {
    CC_SHADER_LANG_SPIRV = 0,
    CC_SHADER_LANG_MSL   = 1,   /* Metal Shading Language */
    CC_SHADER_LANG_HLSL  = 2,
    CC_SHADER_LANG_GLSL  = 3,
    CC_SHADER_LANG_WGSL  = 4,   /* WebGPU */
    CC_SHADER_LANG_DXIL  = 5,
    CC_SHADER_LANG_AIR   = 6,   /* Metal IR */
} cc_shader_lang;

typedef struct {
    cc_shader_stage stage;
    cc_shader_lang  language;
    uint32_t        entry_point_len;    /* length of entry point name */
    uint32_t        uniform_count;
    uint32_t        sampler_count;
    uint32_t        buffer_count;
    uint32_t        source_size;        /* 0 if binary only */
    uint32_t        binary_size;        /* 0 if source only */
    uint8_t         name[32];
} cc_wrap_shader;

/* ── Level / World ── */

typedef struct {
    uint32_t        entity_count;
    uint32_t        layer_count;
    uint32_t        spawn_count;        /* spawn points */
    uint32_t        trigger_count;      /* trigger volumes */
    uint32_t        light_probe_count;
    float           bounds_min[3];
    float           bounds_max[3];
    float           gravity[3];
    uint8_t         streaming;          /* 1 = level supports streaming chunks */
    uint8_t         reserved[3];
    uint8_t         name[32];
} cc_wrap_level;

/* ── Physics (collision / rigid body) ── */

typedef enum {
    CC_PHYS_BOX      = 0,
    CC_PHYS_SPHERE   = 1,
    CC_PHYS_CAPSULE  = 2,
    CC_PHYS_CONVEX   = 3,
    CC_PHYS_TRIMESH  = 4,
    CC_PHYS_HEIGHTMAP= 5,
    CC_PHYS_COMPOUND = 6,
} cc_physics_shape;

typedef struct {
    cc_physics_shape shape;
    uint32_t        shape_count;        /* >1 for compound */
    float           mass;               /* 0 = static */
    float           friction;
    float           restitution;
    float           linear_damping;
    float           angular_damping;
    uint8_t         is_trigger;         /* 1 = trigger volume, no physics */
    uint8_t         is_kinematic;       /* 1 = animated, not simulated */
    uint8_t         collision_group;
    uint8_t         collision_mask;
} cc_wrap_physics;

/* ── Navigation mesh ── */

typedef struct {
    uint32_t        vertex_count;
    uint32_t        polygon_count;
    uint32_t        edge_count;
    float           cell_size;
    float           cell_height;
    float           agent_radius;
    float           agent_height;
    float           max_slope;          /* degrees */
    float           max_step;           /* vertical step height */
    float           bounds_min[3];
    float           bounds_max[3];
} cc_wrap_navmesh;

/* ── Dialogue tree / Localization ── */

typedef struct {
    uint32_t        node_count;
    uint32_t        choice_count;
    uint32_t        string_count;
    uint32_t        language_count;
    uint8_t         default_language[8]; /* ISO 639-1 */
    uint8_t         name[32];
} cc_wrap_dialogue;

/* ── Voxel grid / Volume ── */

typedef struct {
    uint32_t        size_x, size_y, size_z;
    float           voxel_size;         /* world units per voxel */
    cc_pixel_format data_format;
    uint16_t        channels;           /* 1=density, 4=RGBA, N=custom */
    uint16_t        palette_size;       /* 0 = no palette (direct values) */
    uint8_t         sparse;             /* 1 = SVO/octree, 0 = dense array */
    uint8_t         reserved[3];
} cc_wrap_voxel;

/* ── Heightmap terrain ── */

typedef struct {
    uint32_t        resolution;         /* NxN heightmap */
    float           terrain_width;      /* world units */
    float           terrain_depth;
    float           height_min;
    float           height_max;
    cc_pixel_format height_format;      /* typically FLOAT32 or UINT16 */
    uint16_t        splat_layers;       /* number of texture layers */
    uint16_t        detail_layers;      /* grass/vegetation scatter layers */
    uint8_t         has_holes;          /* 1 = supports terrain holes */
    uint8_t         reserved[3];
} cc_wrap_terrain;

/* ── Entity prefab (component bundle) ── */

typedef struct {
    uint32_t        component_count;
    uint32_t        child_count;        /* nested prefab instances */
    uint32_t        variant_count;      /* prefab variants (overrides) */
    uint8_t         name[32];
    uint8_t         tag[16];            /* category tag */
} cc_wrap_prefab;

/* ══════════════════════════════════════════════════════════════
 * Office / productivity wrapper types
 * ══════════════════════════════════════════════════════════════ */

/* ── Spreadsheet ── */

typedef struct {
    uint32_t        sheet_count;
    uint32_t        total_rows;
    uint32_t        total_cols;
    uint32_t        formula_count;
    uint32_t        chart_count;        /* embedded charts */
    uint32_t        named_range_count;
    uint8_t         has_macros;
    uint8_t         has_pivot_tables;
    uint8_t         has_data_validation;
    uint8_t         reserved;
    uint8_t         name[32];
} cc_wrap_spreadsheet;

/* ── Presentation (slide deck) ── */

typedef struct {
    uint32_t        slide_count;
    uint32_t        master_count;       /* slide masters / templates */
    uint32_t        layout_count;
    uint32_t        animation_count;    /* slide transition + object animations */
    uint32_t        media_count;        /* embedded images/video/audio */
    float           aspect_ratio;       /* width/height (e.g., 16/9 = 1.778) */
    uint32_t        width_pt;           /* slide width in points */
    uint32_t        height_pt;
    uint8_t         has_speaker_notes;
    uint8_t         has_comments;
    uint8_t         reserved[2];
    uint8_t         name[32];
} cc_wrap_presentation;

/* ── Rich text (styled document / word processor) ── */

typedef struct {
    uint32_t        page_count;
    uint32_t        section_count;
    uint32_t        paragraph_count;
    uint32_t        image_count;
    uint32_t        table_count;
    uint32_t        footnote_count;
    uint32_t        style_count;        /* named styles */
    uint64_t        word_count;
    uint64_t        char_count;
    uint8_t         has_toc;            /* table of contents */
    uint8_t         has_headers_footers;
    uint8_t         has_track_changes;
    uint8_t         has_comments;
    float           page_width_pt;      /* points */
    float           page_height_pt;
    uint8_t         language[8];
    uint8_t         name[32];
} cc_wrap_richtext;

/* ── Form (input fields + validation) ── */

typedef struct {
    uint32_t        field_count;
    uint32_t        section_count;
    uint32_t        rule_count;         /* validation rules */
    uint32_t        submission_count;   /* stored submissions (0 = template only) */
    uint8_t         has_conditional;    /* conditional field visibility */
    uint8_t         has_scoring;        /* quiz/survey scoring */
    uint8_t         multipage;
    uint8_t         reserved;
    uint8_t         name[32];
} cc_wrap_form;

/* ── Database (structured records) ── */

typedef struct {
    uint32_t        table_count;
    uint32_t        total_rows;
    uint32_t        total_columns;
    uint32_t        index_count;
    uint32_t        view_count;
    uint32_t        relation_count;     /* foreign key / joins */
    uint64_t        data_size;          /* uncompressed row data bytes */
    uint8_t         has_triggers;
    uint8_t         has_stored_procs;
    uint8_t         encoding;           /* 0=UTF-8, 1=UTF-16 */
    uint8_t         reserved;
    uint8_t         name[32];
} cc_wrap_database;

/* ── Chart / graph visualization ── */

typedef enum {
    CC_CHART_BAR       = 0,
    CC_CHART_LINE      = 1,
    CC_CHART_PIE       = 2,
    CC_CHART_SCATTER   = 3,
    CC_CHART_AREA      = 4,
    CC_CHART_RADAR     = 5,
    CC_CHART_BUBBLE    = 6,
    CC_CHART_HEATMAP   = 7,
    CC_CHART_TREEMAP   = 8,
    CC_CHART_SANKEY    = 9,
    CC_CHART_HISTOGRAM = 10,
    CC_CHART_CANDLESTICK = 11,
    CC_CHART_GANTT     = 12,
} cc_chart_type;

typedef struct {
    cc_chart_type   chart_type;
    uint32_t        series_count;
    uint32_t        data_points;
    uint32_t        axis_count;         /* 2=2D, 3=3D */
    uint8_t         stacked;
    uint8_t         horizontal;         /* bar chart orientation */
    uint8_t         has_legend;
    uint8_t         has_labels;
    uint8_t         title[64];
} cc_wrap_chart;

/* ── Diagram / flowchart (vector) ── */

typedef enum {
    CC_DIAG_FLOWCHART  = 0,
    CC_DIAG_ORG_CHART  = 1,
    CC_DIAG_SEQUENCE   = 2,
    CC_DIAG_STATE      = 3,
    CC_DIAG_ER         = 4,     /* entity-relationship */
    CC_DIAG_UML_CLASS  = 5,
    CC_DIAG_NETWORK    = 6,
    CC_DIAG_MIND_MAP   = 7,
    CC_DIAG_KANBAN     = 8,
    CC_DIAG_WIREFRAME  = 9,
    CC_DIAG_FREEFORM   = 10,
} cc_diagram_type;

typedef struct {
    cc_diagram_type diagram_type;
    uint32_t        node_count;
    uint32_t        edge_count;
    uint32_t        group_count;        /* swim lanes / grouping */
    float           canvas_width;
    float           canvas_height;
    uint8_t         auto_layout;        /* 0=manual, 1=auto positioned */
    uint8_t         reserved[3];
} cc_wrap_diagram;

/* ── Calendar / schedule ── */

typedef struct {
    uint32_t        event_count;
    uint32_t        recurring_count;
    uint32_t        timezone_count;
    uint64_t        range_start;        /* unix timestamp */
    uint64_t        range_end;
    uint8_t         has_reminders;
    uint8_t         has_attendees;
    uint8_t         has_locations;
    uint8_t         reserved;
    uint8_t         name[32];
} cc_wrap_calendar;

/* ── Contacts / address book ── */

typedef struct {
    uint32_t        contact_count;
    uint32_t        group_count;
    uint32_t        phone_count;
    uint32_t        email_count;
    uint32_t        address_count;
    uint8_t         has_photos;
    uint8_t         has_notes;
    uint8_t         has_social;
    uint8_t         reserved;
} cc_wrap_contacts;

/* ── Email message ── */

typedef struct {
    uint32_t        attachment_count;
    uint64_t        date;               /* unix timestamp */
    uint64_t        body_size;
    uint32_t        header_count;
    uint8_t         content_type;       /* 0=plain, 1=HTML, 2=multipart */
    uint8_t         has_signature;
    uint8_t         encrypted;          /* S/MIME or PGP */
    uint8_t         signed_msg;
    uint8_t         subject[128];
} cc_wrap_email;

/* ── Computational notebook (Jupyter-like) ── */

typedef struct {
    uint32_t        cell_count;
    uint32_t        code_cells;
    uint32_t        markdown_cells;
    uint32_t        output_cells;       /* cells with cached output */
    uint32_t        image_outputs;
    uint8_t         kernel[32];         /* e.g., "python3", "julia", "R" */
    uint8_t         language[16];
} cc_wrap_notebook;

/* ── Vector graphics (SVG-like) ── */

typedef struct {
    uint32_t        element_count;      /* total paths, shapes, groups */
    uint32_t        path_count;
    uint32_t        group_count;
    uint32_t        gradient_count;
    uint32_t        filter_count;
    float           viewbox_width;
    float           viewbox_height;
    float           canvas_width;       /* physical size (0 = scale to viewbox) */
    float           canvas_height;
    uint8_t         has_text;
    uint8_t         has_animation;      /* SMIL / CSS animation */
    uint8_t         has_interactivity;  /* scripts / event handlers */
    uint8_t         reserved;
} cc_wrap_vector;

/* ── Custom (user-defined) ── */

typedef struct {
    uint8_t         ext_type[16];   /* user-defined type identifier */
    uint32_t        ext_version;
    uint32_t        ext_data_size;  /* size of following user data */
} cc_wrap_custom;

/* ── Asset reference (can appear in any wrapper as a sub-entry) ── */

typedef struct {
    uint8_t         hash[32];       /* SHA3-256 of referenced .cute file */
    uint32_t        ref_type;       /* 0=embed, 1=external, 2=network */
    uint32_t        path_len;
    /* followed by path_len bytes of UTF-8 path */
} cc_wrap_ref;

/* ── Variant (alternative representation) ── */

typedef struct {
    uint8_t         name[32];       /* variant name, e.g. "proxy", "hdr", "lod0" */
    uint32_t        wrap_type;      /* what this variant wraps */
    uint64_t        payload_offset; /* byte offset into container payload */
    uint64_t        payload_size;
} cc_wrap_variant;

/* ──────────────────────────────────────────────────────────────
 * Wrapper collection (in-memory, read from container meta)
 * ────────────────────────────────────────────────────────────── */

#define CC_MAX_WRAPS       16
#define CC_MAX_VARIANTS    8
#define CC_MAX_REFS        32

typedef struct {
    cc_wrap_type    type;
    uint32_t        size;       /* total serialized size */
    const void     *data;       /* pointer to type-specific struct */
} cc_wrap_entry;

typedef struct {
    uint32_t        count;
    cc_wrap_entry   wraps[CC_MAX_WRAPS];

    uint32_t        variant_count;
    cc_wrap_variant variants[CC_MAX_VARIANTS];

    uint32_t        ref_count;
    cc_wrap_ref     refs[CC_MAX_REFS];
} cc_wrap_set;

/* ──────────────────────────────────────────────────────────────
 * API
 * ────────────────────────────────────────────────────────────── */

/* Initialize an empty wrap set. */
void cc_wrap_init(cc_wrap_set *ws);

/* Add a wrapper to the set. Data is copied. */
int cc_wrap_add(cc_wrap_set *ws, cc_wrap_type type, const void *data, size_t size);

/* Add a variant. */
int cc_wrap_add_variant(cc_wrap_set *ws, const cc_wrap_variant *v);

/* Add an asset reference. */
int cc_wrap_add_ref(cc_wrap_set *ws, const cc_wrap_ref *r);

/* Find a wrapper by type. Returns pointer to data or NULL. */
const void *cc_wrap_find(const cc_wrap_set *ws, cc_wrap_type type, size_t *size);

/* Serialize wrap set to a buffer (for storing in container meta).
 * Caller must free *out. */
int cc_wrap_serialize(const cc_wrap_set *ws, uint8_t **out, size_t *out_len);

/* Deserialize wrap set from buffer (read from container meta).
 * data must remain valid for the lifetime of ws. */
int cc_wrap_deserialize(cc_wrap_set *ws, const uint8_t *data, size_t len);

/* Human-readable name for a wrap type. */
const char *cc_wrap_type_name(cc_wrap_type type);

/* ──────────────────────────────────────────────────────────────
 * Import bridges — convert external formats to wrapped .cute
 *
 * Each bridge reads an external format, creates the appropriate
 * wrappers, and writes a .cute container.
 * ────────────────────────────────────────────────────────────── */

/* Describe an external file (probe without converting).
 * Fills wrap set with what WOULD be created. */
int cc_wrap_probe_file(const char *path, cc_wrap_set *ws);

/* Import an external file into a .cute container with wrappers.
 * Detects format from extension/magic, creates appropriate wrappers. */
int cc_wrap_import(const char *in_path, const char *out_path, int compress);

/* Export a wrapped .cute container to an external format.
 * Target format determined by out_path extension. */
int cc_wrap_export(const char *in_path, const char *out_path);

#ifdef __cplusplus
}
#endif

#endif /* CUTECONTAINER_WRAP_H */
