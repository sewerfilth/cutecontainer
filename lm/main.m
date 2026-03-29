/*
 * cutecontainer-lm — native macOS archive manager
 *
 * Tab-based: File Browser | Container Inspector
 * Back button with enable/disable, context menus,
 * archive browsing, selection-aware actions.
 */

#if defined(__APPLE__)

#import <Cocoa/Cocoa.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>
#include "cutecontainer/sdk.h"
#include "cutecontainer/container.h"
#include "cutecontainer/archive.h"

/* forward */
@interface DropWindow : NSWindow @end
@class App;

static NSString *hSz(uint64_t b) {
    if (b<1024) return [NSString stringWithFormat:@"%llu B",b];
    if (b<1048576) return [NSString stringWithFormat:@"%.1f KB",b/1024.0];
    if (b<1073741824) return [NSString stringWithFormat:@"%.1f MB",b/1048576.0];
    return [NSString stringWithFormat:@"%.2f GB",b/1073741824.0];
}

static BOOL isArchiveExt(NSString *ext) {
    return [@[@"zip",@"cute",@"press",@"7z",@"tar",@"gz",@"bz2",@"xz",@"rar"] containsObject:ext.lowercaseString];
}

static NSImage *iconFor(NSString *ext, BOOL isDir) {
    if (isDir) return [NSImage imageWithSystemSymbolName:@"folder.fill" accessibilityDescription:@""];
    NSDictionary *m = @{
        @"png":@"photo",@"jpg":@"photo",@"jpeg":@"photo",@"gif":@"photo",@"webp":@"photo",
        @"tiff":@"photo",@"exr":@"photo",@"bmp":@"photo",@"psd":@"photo",
        @"mp4":@"film",@"mov":@"film",@"mkv":@"film",
        @"mp3":@"music.note",@"wav":@"music.note",@"flac":@"music.note",
        @"zip":@"doc.zipper",@"7z":@"doc.zipper",@"tar":@"doc.zipper",@"gz":@"doc.zipper",
        @"rar":@"doc.zipper",@"cute":@"doc.zipper",@"press":@"doc.zipper",
        @"pdf":@"doc.richtext",@"txt":@"doc.text",@"md":@"doc.text",
        @"json":@"curlybraces",@"html":@"globe",@"css":@"paintbrush",
        @"c":@"chevron.left.forwardslash.chevron.right",
        @"h":@"chevron.left.forwardslash.chevron.right",
        @"m":@"chevron.left.forwardslash.chevron.right",
        @"py":@"curlybraces",@"rs":@"curlybraces",@"swift":@"curlybraces",
        @"obj":@"cube",@"fbx":@"cube",@"gltf":@"cube",
        @"exe":@"terminal",@"sh":@"terminal",
        @"xlsx":@"tablecells",@"docx":@"doc.richtext",
    };
    return [NSImage imageWithSystemSymbolName:(m[ext.lowercaseString]?:@"doc") accessibilityDescription:@""];
}

/* ── Model ── */

@interface FE : NSObject
@property (strong) NSString *name, *path, *ext, *diskPath;
@property uint64_t size, compSize;
@property BOOL isDir;
@end
@implementation FE @end

/* ── Grid item ── */

@interface GI : NSCollectionViewItem
@property (strong) NSTrackingArea *ta;
@end

@implementation GI
- (void)loadView {
    NSView *v = [[NSView alloc] initWithFrame:NSZeroRect];
    v.wantsLayer = YES;
    v.layer.cornerRadius = 10;
    v.layer.cornerCurve = kCACornerCurveContinuous;
    v.layer.backgroundColor = [NSColor colorWithWhite:1 alpha:0.03].CGColor;

    NSImageView *iv = [[NSImageView alloc] init];
    iv.translatesAutoresizingMaskIntoConstraints = NO;
    iv.tag = 1;
    [v addSubview:iv];

    NSTextField *nm = [NSTextField labelWithString:@""];
    nm.translatesAutoresizingMaskIntoConstraints = NO;
    nm.font = [NSFont systemFontOfSize:11 weight:NSFontWeightMedium];
    nm.alignment = NSTextAlignmentCenter;
    nm.lineBreakMode = NSLineBreakByTruncatingMiddle;
    nm.maximumNumberOfLines = 2;
    nm.tag = 2;
    [v addSubview:nm];

    NSTextField *sz = [NSTextField labelWithString:@""];
    sz.translatesAutoresizingMaskIntoConstraints = NO;
    sz.font = [NSFont systemFontOfSize:9];
    sz.textColor = NSColor.tertiaryLabelColor;
    sz.alignment = NSTextAlignmentCenter;
    sz.tag = 3;
    [v addSubview:sz];

    [NSLayoutConstraint activateConstraints:@[
        [iv.centerXAnchor constraintEqualToAnchor:v.centerXAnchor],
        [iv.topAnchor constraintEqualToAnchor:v.topAnchor constant:14],
        [iv.widthAnchor constraintEqualToConstant:32],
        [iv.heightAnchor constraintEqualToConstant:32],
        [nm.topAnchor constraintEqualToAnchor:iv.bottomAnchor constant:6],
        [nm.leadingAnchor constraintEqualToAnchor:v.leadingAnchor constant:4],
        [nm.trailingAnchor constraintEqualToAnchor:v.trailingAnchor constant:-4],
        [sz.topAnchor constraintEqualToAnchor:nm.bottomAnchor constant:1],
        [sz.centerXAnchor constraintEqualToAnchor:v.centerXAnchor],
    ]];
    self.view = v;
}

- (void)setRepresentedObject:(id)o {
    [super setRepresentedObject:o];
    FE *e = o; if (!e) return;
    NSImageView *iv = [self.view viewWithTag:1];
    ((NSTextField *)[self.view viewWithTag:2]).stringValue = e.name;
    ((NSTextField *)[self.view viewWithTag:3]).stringValue = (!e.isDir && e.size) ? hSz(e.size) : @"";
    iv.image = iconFor(e.ext, e.isDir);
    iv.contentTintColor = e.isDir ? NSColor.systemBlueColor :
                          isArchiveExt(e.ext) ? NSColor.systemOrangeColor : NSColor.secondaryLabelColor;
    iv.symbolConfiguration = [NSImageSymbolConfiguration configurationWithPointSize:e.isDir?24:20
        weight:e.isDir ? NSFontWeightRegular : NSFontWeightLight];
    self.view.layer.backgroundColor = [NSColor colorWithWhite:1 alpha:0.03].CGColor;
}

- (void)setSelected:(BOOL)s {
    [super setSelected:s];
    self.view.layer.backgroundColor = s ?
        [NSColor.controlAccentColor colorWithAlphaComponent:0.18].CGColor :
        [NSColor colorWithWhite:1 alpha:0.03].CGColor;
}

- (void)updateTrackingAreas {
    [super updateTrackingAreas];
    if (self.ta) [self.view removeTrackingArea:self.ta];
    self.ta = [[NSTrackingArea alloc] initWithRect:self.view.bounds
        options:NSTrackingMouseEnteredAndExited|NSTrackingActiveInActiveApp|NSTrackingInVisibleRect
        owner:self userInfo:nil];
    [self.view addTrackingArea:self.ta];
}
- (void)mouseEntered:(NSEvent *)e { (void)e; if (!self.isSelected)
    self.view.layer.backgroundColor = [NSColor colorWithWhite:1 alpha:0.07].CGColor; }
- (void)mouseExited:(NSEvent *)e { (void)e; if (!self.isSelected)
    self.view.layer.backgroundColor = [NSColor colorWithWhite:1 alpha:0.03].CGColor; }
@end

/* ── Responsive layout ── */

@interface RFL : NSCollectionViewFlowLayout @end
@implementation RFL
- (void)prepareLayout {
    [super prepareLayout];
    CGFloat w = self.collectionView.bounds.size.width, m = 20, g = 8, mn = 96, mx = 120;
    CGFloat u = w - m*2;
    int c = MAX(1, (int)((u+g)/(mn+g)));
    CGFloat iw = MIN(mx, (u-g*(c-1))/c);
    self.itemSize = NSMakeSize(iw, iw);
    self.minimumInteritemSpacing = g;
    self.minimumLineSpacing = g;
    self.sectionInset = NSEdgeInsetsMake(14, m, 14, m);
}
- (BOOL)shouldInvalidateLayoutForBoundsChange:(NSRect)b { (void)b; return YES; }
@end

/* ══════════════════════════════════════════════════════════════ */

typedef enum { TAB_BROWSER = 0, TAB_INSPECTOR = 1 } TabMode;

@interface App : NSObject <NSApplicationDelegate, NSToolbarDelegate,
                            NSCollectionViewDataSource, NSCollectionViewDelegate>
@property (strong) DropWindow *win;
@property (strong) NSCollectionView *grid;
@property (strong) NSTextField *status;
@property (strong) NSStackView *bc;
@property (strong) NSView *empty, *inspectorView;
@property (strong) NSScrollView *gridScroll;
@property (strong) NSProgressIndicator *prog;
@property (strong) NSSegmentedControl *tabs;
@property (strong) NSToolbarItem *backItem;
@property (strong) NSMutableArray<FE *> *vis, *all;
@property (strong) NSString *curDir, *rootPath;
@property TabMode mode;
@property BOOL browsingArchive;
@property (assign) cc_archive *openArchive;
@end

@implementation App

- (void)applicationDidFinishLaunching:(NSNotification *)n {
    (void)n;
    cc_sdk_init_full();
    self.vis = [NSMutableArray new];
    self.all = [NSMutableArray new];
    self.curDir = @"";
    self.mode = TAB_BROWSER;

    NSRect f = NSMakeRect(0, 0, 860, 580);
    self.win = [[DropWindow alloc]
        initWithContentRect:f
        styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|
                  NSWindowStyleMaskMiniaturizable|NSWindowStyleMaskResizable|
                  NSWindowStyleMaskUnifiedTitleAndToolbar
        backing:NSBackingStoreBuffered defer:NO];
    self.win.title = @"cutecontainer";
    self.win.minSize = NSMakeSize(420, 320);
    self.win.backgroundColor = [NSColor colorWithWhite:0.105 alpha:1];
    self.win.appearance = [NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
    [self.win registerForDraggedTypes:@[NSPasteboardTypeFileURL]];
    [self.win center];

    NSToolbar *tb = [[NSToolbar alloc] initWithIdentifier:@"t"];
    tb.delegate = self;
    tb.displayMode = NSToolbarDisplayModeIconOnly;
    self.win.toolbar = tb;

    NSView *root = self.win.contentView;

    /* tab bar + breadcrumb row */
    NSView *topBar = [[NSView alloc] init];
    topBar.translatesAutoresizingMaskIntoConstraints = NO;
    topBar.wantsLayer = YES;
    topBar.layer.backgroundColor = [NSColor colorWithWhite:0.09 alpha:1].CGColor;
    [root addSubview:topBar];

    self.tabs = [NSSegmentedControl segmentedControlWithLabels:@[@"Browser", @"Inspector"]
        trackingMode:NSSegmentSwitchTrackingSelectOne target:self action:@selector(tabChanged:)];
    self.tabs.selectedSegment = 0;
    self.tabs.translatesAutoresizingMaskIntoConstraints = NO;
    self.tabs.controlSize = NSControlSizeSmall;
    [topBar addSubview:self.tabs];

    self.bc = [NSStackView stackViewWithViews:@[]];
    self.bc.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    self.bc.spacing = 2;
    self.bc.translatesAutoresizingMaskIntoConstraints = NO;
    self.bc.edgeInsets = NSEdgeInsetsMake(0, 8, 0, 0);
    [topBar addSubview:self.bc];

    [NSLayoutConstraint activateConstraints:@[
        [topBar.topAnchor constraintEqualToAnchor:root.topAnchor],
        [topBar.leadingAnchor constraintEqualToAnchor:root.leadingAnchor],
        [topBar.trailingAnchor constraintEqualToAnchor:root.trailingAnchor],
        [topBar.heightAnchor constraintEqualToConstant:30],
        [self.tabs.leadingAnchor constraintEqualToAnchor:topBar.leadingAnchor constant:12],
        [self.tabs.centerYAnchor constraintEqualToAnchor:topBar.centerYAnchor],
        [self.bc.leadingAnchor constraintEqualToAnchor:self.tabs.trailingAnchor constant:12],
        [self.bc.trailingAnchor constraintEqualToAnchor:topBar.trailingAnchor constant:-12],
        [self.bc.centerYAnchor constraintEqualToAnchor:topBar.centerYAnchor],
    ]];

    /* progress */
    self.prog = [[NSProgressIndicator alloc] init];
    self.prog.translatesAutoresizingMaskIntoConstraints = NO;
    self.prog.style = NSProgressIndicatorStyleBar;
    self.prog.hidden = YES;
    [root addSubview:self.prog];

    /* grid */
    self.gridScroll = [[NSScrollView alloc] init];
    self.gridScroll.translatesAutoresizingMaskIntoConstraints = NO;
    self.gridScroll.hasVerticalScroller = YES;
    self.gridScroll.scrollerStyle = NSScrollerStyleOverlay;
    self.gridScroll.borderType = NSNoBorder;
    self.gridScroll.drawsBackground = NO;

    self.grid = [[NSCollectionView alloc] init];
    self.grid.collectionViewLayout = [[RFL alloc] init];
    self.grid.dataSource = self;
    self.grid.delegate = self;
    self.grid.backgroundColors = @[[NSColor clearColor]];
    self.grid.selectable = YES;
    self.grid.allowsMultipleSelection = YES;
    [self.grid registerClass:[GI class] forItemWithIdentifier:@"i"];
    self.gridScroll.documentView = self.grid;
    [root addSubview:self.gridScroll];

    /* inspector view (hidden by default) */
    self.inspectorView = [[NSView alloc] init];
    self.inspectorView.translatesAutoresizingMaskIntoConstraints = NO;
    self.inspectorView.hidden = YES;
    [root addSubview:self.inspectorView];

    /* status */
    self.status = [NSTextField labelWithString:@""];
    self.status.font = [NSFont systemFontOfSize:11];
    self.status.textColor = NSColor.tertiaryLabelColor;
    self.status.translatesAutoresizingMaskIntoConstraints = NO;
    [root addSubview:self.status];

    /* empty state */
    self.empty = [[NSView alloc] init];
    self.empty.translatesAutoresizingMaskIntoConstraints = NO;
    [root addSubview:self.empty];

    NSImageView *ei = [[NSImageView alloc] init];
    ei.translatesAutoresizingMaskIntoConstraints = NO;
    ei.image = [NSImage imageWithSystemSymbolName:@"doc.zipper" accessibilityDescription:@""];
    ei.symbolConfiguration = [NSImageSymbolConfiguration configurationWithPointSize:40 weight:NSFontWeightUltraLight];
    ei.contentTintColor = [NSColor colorWithWhite:0.28 alpha:1];
    [self.empty addSubview:ei];

    NSTextField *et = [NSTextField labelWithString:@"Drop files or folders to browse"];
    et.font = [NSFont systemFontOfSize:14 weight:NSFontWeightMedium];
    et.textColor = [NSColor colorWithWhite:0.38 alpha:1];
    et.translatesAutoresizingMaskIntoConstraints = NO;
    et.alignment = NSTextAlignmentCenter;
    [self.empty addSubview:et];

    [NSLayoutConstraint activateConstraints:@[
        [self.prog.topAnchor constraintEqualToAnchor:topBar.bottomAnchor],
        [self.prog.leadingAnchor constraintEqualToAnchor:root.leadingAnchor],
        [self.prog.trailingAnchor constraintEqualToAnchor:root.trailingAnchor],
        [self.prog.heightAnchor constraintEqualToConstant:2],
        [self.gridScroll.topAnchor constraintEqualToAnchor:self.prog.bottomAnchor],
        [self.gridScroll.leadingAnchor constraintEqualToAnchor:root.leadingAnchor],
        [self.gridScroll.trailingAnchor constraintEqualToAnchor:root.trailingAnchor],
        [self.gridScroll.bottomAnchor constraintEqualToAnchor:self.status.topAnchor constant:-4],
        [self.inspectorView.topAnchor constraintEqualToAnchor:self.prog.bottomAnchor],
        [self.inspectorView.leadingAnchor constraintEqualToAnchor:root.leadingAnchor],
        [self.inspectorView.trailingAnchor constraintEqualToAnchor:root.trailingAnchor],
        [self.inspectorView.bottomAnchor constraintEqualToAnchor:self.status.topAnchor constant:-4],
        [self.status.leadingAnchor constraintEqualToAnchor:root.leadingAnchor constant:14],
        [self.status.trailingAnchor constraintEqualToAnchor:root.trailingAnchor constant:-14],
        [self.status.bottomAnchor constraintEqualToAnchor:root.bottomAnchor constant:-5],
        [self.status.heightAnchor constraintEqualToConstant:14],
        [self.empty.centerXAnchor constraintEqualToAnchor:root.centerXAnchor],
        [self.empty.centerYAnchor constraintEqualToAnchor:root.centerYAnchor],
        [self.empty.widthAnchor constraintEqualToConstant:300],
        [self.empty.heightAnchor constraintEqualToConstant:80],
        [ei.centerXAnchor constraintEqualToAnchor:self.empty.centerXAnchor],
        [ei.topAnchor constraintEqualToAnchor:self.empty.topAnchor],
        [et.centerXAnchor constraintEqualToAnchor:self.empty.centerXAnchor],
        [et.topAnchor constraintEqualToAnchor:ei.bottomAnchor constant:10],
    ]];

    /* double-click + right-click */
    NSClickGestureRecognizer *dbl = [[NSClickGestureRecognizer alloc]
        initWithTarget:self action:@selector(dblClick:)];
    dbl.numberOfClicksRequired = 2;
    dbl.delaysPrimaryMouseButtonEvents = NO;
    [self.grid addGestureRecognizer:dbl];

    self.grid.menu = [self buildContextMenu];

    [self setupMenu];
    [self.win makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

/* ── Context menu ── */

- (NSMenu *)buildContextMenu {
    NSMenu *m = [[NSMenu alloc] init];
    [m addItemWithTitle:@"Open" action:@selector(ctxOpen:) keyEquivalent:@""];
    [m addItemWithTitle:@"Get Info" action:@selector(doInfo:) keyEquivalent:@""];
    [m addItem:[NSMenuItem separatorItem]];
    [m addItemWithTitle:@"Compress" action:@selector(ctxCompress:) keyEquivalent:@""];
    [m addItemWithTitle:@"Extract" action:@selector(doExtract:) keyEquivalent:@""];
    [m addItem:[NSMenuItem separatorItem]];
    [m addItemWithTitle:@"Reveal in Finder" action:@selector(ctxReveal:) keyEquivalent:@""];
    return m;
}

- (FE *)selectedEntry {
    NSSet<NSIndexPath *> *sel = self.grid.selectionIndexPaths;
    if (sel.count != 1) return nil;
    return self.vis[sel.anyObject.item];
}

- (void)ctxOpen:(id)s { (void)s;
    FE *e = [self selectedEntry]; if (!e) return;
    if (e.isDir) { self.curDir = e.path; [self reload]; }
    else if (e.diskPath && isArchiveExt(e.ext)) [self openArchiveFile:e.diskPath];
    else if (e.diskPath) [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:e.diskPath]];
}

- (void)ctxCompress:(id)s { (void)s;
    FE *e = [self selectedEntry]; if (!e || !e.diskPath) return;
    [self compressPath:e.diskPath];
}

- (void)ctxReveal:(id)s { (void)s;
    FE *e = [self selectedEntry]; if (!e || !e.diskPath) return;
    [[NSWorkspace sharedWorkspace] selectFile:e.diskPath
        inFileViewerRootedAtPath:e.diskPath.stringByDeletingLastPathComponent];
}

/* ── Tab switching ── */

- (void)tabChanged:(NSSegmentedControl *)seg {
    self.mode = (TabMode)seg.selectedSegment;
    self.gridScroll.hidden = (self.mode == TAB_INSPECTOR);
    self.inspectorView.hidden = (self.mode == TAB_BROWSER);
    if (self.mode == TAB_INSPECTOR) [self buildInspector];
}

- (void)buildInspector {
    for (NSView *v in [self.inspectorView.subviews copy]) [v removeFromSuperview];

    NSMutableString *info = [NSMutableString string];
    [info appendFormat:@"Path: %@\n", self.rootPath ?: @"(none)"];

    if (self.browsingArchive && self.openArchive) {
        cc_archive_format fmt = cc_archive_format_of(self.openArchive);
        int count = cc_archive_count(self.openArchive);
        [info appendFormat:@"Format: %s\n", cc_archive_format_name(fmt)];
        [info appendFormat:@"Entries: %d\n", count];
        uint64_t total = 0, comp = 0;
        for (int i = 0; i < count; i++) {
            const cc_archive_entry *e = cc_archive_entry_at(self.openArchive, i);
            if (e) { total += e->size; comp += e->compressed_size; }
        }
        [info appendFormat:@"Original: %@\n", hSz(total)];
        if (comp) [info appendFormat:@"Compressed: %@ (%.1f%%)\n", hSz(comp), (double)comp/(double)total*100.0];
    } else if (self.rootPath) {
        /* detect cutecontainer type */
        FILE *f = fopen(self.rootPath.UTF8String, "rb");
        if (f) {
            uint8_t hdr[64]; size_t rd = fread(hdr, 1, 64, f); fclose(f);
            cc_content_type type = cc_container_detect(hdr, rd);
            if (type != CC_TYPE_UNKNOWN) {
                [info appendFormat:@"Container: %s\n", cc_content_type_name(type)];
                const cc_module *mod = cc_probe_module(hdr, rd);
                if (mod) {
                    [info appendFormat:@"Module: %s\n", mod->name];
                    char buf[2048] = {0};
                    /* reread full file for info */
                    FILE *ff = fopen(self.rootPath.UTF8String, "rb");
                    if (ff) {
                        fseek(ff,0,SEEK_END); size_t fl=(size_t)ftell(ff); fseek(ff,0,SEEK_SET);
                        uint8_t *data=malloc(fl); fread(data,1,fl,ff); fclose(ff);
                        if (mod->info) mod->info(data, fl, buf, sizeof(buf));
                        free(data);
                    }
                    if (buf[0]) [info appendFormat:@"\n%s", buf];
                }
            }
        }

        const cc_module *mods[32];
        int n = cc_list_modules(mods, 32);
        [info appendFormat:@"\n\nModules (%d):\n", n];
        for (int i = 0; i < n; i++)
            [info appendFormat:@"  %s — %s\n", mods[i]->name, mods[i]->description];
    }

    NSScrollView *sc = [[NSScrollView alloc] init];
    sc.translatesAutoresizingMaskIntoConstraints = NO;
    sc.hasVerticalScroller = YES;
    sc.borderType = NSNoBorder;
    sc.drawsBackground = NO;

    NSTextView *tv = [[NSTextView alloc] init];
    tv.editable = NO;
    tv.drawsBackground = NO;
    tv.font = [NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular];
    tv.textColor = NSColor.secondaryLabelColor;
    tv.textContainerInset = NSMakeSize(20, 16);
    tv.string = info;
    sc.documentView = tv;
    [self.inspectorView addSubview:sc];

    [NSLayoutConstraint activateConstraints:@[
        [sc.topAnchor constraintEqualToAnchor:self.inspectorView.topAnchor],
        [sc.bottomAnchor constraintEqualToAnchor:self.inspectorView.bottomAnchor],
        [sc.leadingAnchor constraintEqualToAnchor:self.inspectorView.leadingAnchor],
        [sc.trailingAnchor constraintEqualToAnchor:self.inspectorView.trailingAnchor],
    ]];
}

/* ── Menu ── */

- (void)setupMenu {
    NSMenu *bar = [[NSMenu alloc] init];
    NSMenuItem *ai = [bar addItemWithTitle:@"" action:nil keyEquivalent:@""];
    NSMenu *am = [[NSMenu alloc] init];
    [am addItemWithTitle:@"About cutecontainer" action:@selector(orderFrontStandardAboutPanel:) keyEquivalent:@""];
    [am addItem:[NSMenuItem separatorItem]];
    [am addItemWithTitle:@"Quit" action:@selector(terminate:) keyEquivalent:@"q"];
    ai.submenu = am;

    NSMenuItem *fi = [bar addItemWithTitle:@"" action:nil keyEquivalent:@""];
    NSMenu *fm = [[NSMenu alloc] initWithTitle:@"File"];
    [fm addItemWithTitle:@"Open\u2026" action:@selector(doOpen:) keyEquivalent:@"o"];
    [fm addItemWithTitle:@"Compress\u2026" action:@selector(doCompress:) keyEquivalent:@"k"];
    [fm addItemWithTitle:@"Extract\u2026" action:@selector(doExtract:) keyEquivalent:@"e"];
    [fm addItem:[NSMenuItem separatorItem]];
    [fm addItemWithTitle:@"Get Info" action:@selector(doInfo:) keyEquivalent:@"i"];
    [fm addItem:[NSMenuItem separatorItem]];
    [fm addItemWithTitle:@"Back" action:@selector(doBack:) keyEquivalent:@"["];
    fi.submenu = fm;
    NSApp.mainMenu = bar;
}

/* ── Toolbar ── */

- (NSArray<NSToolbarItemIdentifier> *)toolbarAllowedItemIdentifiers:(NSToolbar *)t {
    (void)t; return @[@"back",@"open",@"compress",@"extract",@"info",NSToolbarFlexibleSpaceItemIdentifier];
}
- (NSArray<NSToolbarItemIdentifier> *)toolbarDefaultItemIdentifiers:(NSToolbar *)t {
    (void)t; return @[@"back",NSToolbarFlexibleSpaceItemIdentifier,@"open",@"compress",@"extract",@"info"];
}
- (NSToolbarItem *)toolbar:(NSToolbar *)t itemForItemIdentifier:(NSToolbarItemIdentifier)ident
    willBeInsertedIntoToolbar:(BOOL)f {
    (void)t;(void)f;
    NSToolbarItem *it = [[NSToolbarItem alloc] initWithItemIdentifier:ident];
    NSDictionary *map = @{
        @"back":    @[@"Back",    @"chevron.left",     NSStringFromSelector(@selector(doBack:))],
        @"open":    @[@"Open",    @"folder",            NSStringFromSelector(@selector(doOpen:))],
        @"compress":@[@"Compress",@"arrow.down.to.line",NSStringFromSelector(@selector(doCompress:))],
        @"extract": @[@"Extract", @"arrow.up.doc",      NSStringFromSelector(@selector(doExtract:))],
        @"info":    @[@"Info",    @"info.circle",       NSStringFromSelector(@selector(doInfo:))],
    };
    NSArray *cfg = map[ident];
    if (cfg) {
        it.label = cfg[0];
        it.image = [NSImage imageWithSystemSymbolName:cfg[1] accessibilityDescription:cfg[0]];
        it.target = self;
        it.action = NSSelectorFromString(cfg[2]);
    }
    if ([ident isEqualToString:@"back"]) self.backItem = it;
    return it;
}

- (BOOL)validateToolbarItem:(NSToolbarItem *)it {
    if ([it.itemIdentifier isEqualToString:@"back"])
        return self.curDir.length > 0;
    return YES;
}

/* ── Grid data ── */

- (NSInteger)collectionView:(NSCollectionView *)cv numberOfItemsInSection:(NSInteger)s {
    (void)cv;(void)s; return (NSInteger)self.vis.count;
}
- (NSCollectionViewItem *)collectionView:(NSCollectionView *)cv
    itemForRepresentedObjectAtIndexPath:(NSIndexPath *)ip {
    GI *it = [cv makeItemWithIdentifier:@"i" forIndexPath:ip];
    it.representedObject = self.vis[ip.item];
    return it;
}

/* ── Double-click ── */

- (void)dblClick:(NSClickGestureRecognizer *)gr {
    NSPoint pt = [gr locationInView:self.grid];
    NSIndexPath *ip = [self.grid indexPathForItemAtPoint:pt];
    if (!ip || ip.item >= (NSInteger)self.vis.count) return;
    FE *e = self.vis[ip.item];
    if (e.isDir) {
        self.curDir = e.path;
        [self reload];
    } else if (e.diskPath && isArchiveExt(e.ext)) {
        [self openArchiveFile:e.diskPath];
    } else if (e.diskPath) {
        [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:e.diskPath]];
    }
}

/* ── Open ── */

- (void)doOpen:(id)s {
    (void)s;
    NSOpenPanel *p = [NSOpenPanel openPanel];
    p.canChooseDirectories = YES;
    if ([p runModal] == NSModalResponseOK) [self openPath:p.URL.path];
}

- (void)openPath:(NSString *)path {
    BOOL isDir = NO;
    [[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDir];
    if (isDir) [self browseDir:path];
    else if (isArchiveExt(path.pathExtension)) [self openArchiveFile:path];
    else [self browseDir:path.stringByDeletingLastPathComponent];
}

/* ── Browse real directory ── */

- (void)browseDir:(NSString *)path {
    if (self.openArchive) { cc_archive_close(self.openArchive); self.openArchive = nil; }
    self.browsingArchive = NO;
    self.rootPath = path;
    self.curDir = @"";
    [self.all removeAllObjects];

    self.prog.hidden = NO; self.prog.indeterminate = YES; [self.prog startAnimation:nil];
    self.status.stringValue = @"Scanning\u2026";

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSFileManager *fm = [NSFileManager defaultManager];
        NSDirectoryEnumerator *en = [fm enumeratorAtPath:path];
        NSMutableArray<FE *> *entries = [NSMutableArray new];
        NSString *rel;
        while ((rel = [en nextObject])) {
            if ([rel.lastPathComponent hasPrefix:@"."]) { [en skipDescendants]; continue; }
            BOOL isDir = NO;
            NSString *full = [path stringByAppendingPathComponent:rel];
            [fm fileExistsAtPath:full isDirectory:&isDir];
            FE *e = [FE new];
            e.path = rel; e.name = rel.lastPathComponent; e.ext = rel.pathExtension;
            e.isDir = isDir; e.diskPath = full;
            if (!isDir) { NSDictionary *a = [fm attributesOfItemAtPath:full error:nil]; e.size = [a[NSFileSize] unsignedLongLongValue]; }
            [entries addObject:e];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.all setArray:entries];
            self.empty.hidden = YES;
            self.win.title = path.lastPathComponent;
            self.prog.hidden = YES; [self.prog stopAnimation:nil];
            [self reload];
        });
    });
}

/* ── Open archive file (browse contents without extracting) ── */

- (void)openArchiveFile:(NSString *)path {
    if (self.openArchive) { cc_archive_close(self.openArchive); self.openArchive = nil; }

    self.openArchive = cc_archive_open(path.UTF8String);
    if (!self.openArchive) {
        /* fallback: browse parent directory */
        [self browseDir:path.stringByDeletingLastPathComponent];
        self.status.stringValue = [NSString stringWithFormat:@"Cannot read %@ as archive", path.lastPathComponent];
        return;
    }

    self.browsingArchive = YES;
    self.rootPath = path;
    self.curDir = @"";
    [self.all removeAllObjects];

    int count = cc_archive_count(self.openArchive);
    for (int i = 0; i < count; i++) {
        const cc_archive_entry *ae = cc_archive_entry_at(self.openArchive, i);
        if (!ae) continue;
        FE *e = [FE new];
        e.path = [NSString stringWithUTF8String:ae->path];
        e.name = e.path.lastPathComponent;
        e.ext = e.path.pathExtension;
        e.size = ae->size;
        e.compSize = ae->compressed_size;
        e.isDir = ae->is_dir;
        [self.all addObject:e];
    }

    self.empty.hidden = YES;
    self.win.title = [NSString stringWithFormat:@"%@ — %s",
        path.lastPathComponent, cc_archive_format_name(cc_archive_format_of(self.openArchive))];
    [self reload];
}

/* ── Filter + reload ── */

- (void)reload {
    [self.vis removeAllObjects];
    NSMutableSet *dirs = [NSMutableSet new];
    NSString *pfx = self.curDir.length ? [self.curDir stringByAppendingString:@"/"] : @"";
    NSUInteger pl = pfx.length;

    for (FE *e in self.all) {
        if (pl && ![e.path hasPrefix:pfx]) continue;
        NSString *rem = [e.path substringFromIndex:pl];
        if (!rem.length) continue;

        NSRange slash = [rem rangeOfString:@"/"];
        if (slash.location != NSNotFound) {
            NSString *dn = [rem substringToIndex:slash.location];
            if (![dirs containsObject:dn]) {
                [dirs addObject:dn];
                FE *d = [FE new];
                d.name = dn;
                d.path = pl ? [NSString stringWithFormat:@"%@/%@",self.curDir,dn] : dn;
                d.isDir = YES;
                if (self.rootPath && !self.browsingArchive)
                    d.diskPath = [self.rootPath stringByAppendingPathComponent:d.path];
                [self.vis addObject:d];
            }
        } else {
            FE *c = [FE new]; c.name = rem; c.path = e.path; c.ext = e.ext;
            c.size = e.size; c.compSize = e.compSize; c.isDir = e.isDir; c.diskPath = e.diskPath;
            [self.vis addObject:c];
        }
    }

    [self.vis sortUsingComparator:^NSComparisonResult(FE *a, FE *b) {
        if (a.isDir != b.isDir) return a.isDir ? NSOrderedAscending : NSOrderedDescending;
        return [a.name caseInsensitiveCompare:b.name];
    }];

    [self.grid reloadData];
    [self updateBC];
    [self updateStatus];
    [self.win.toolbar validateVisibleItems];
}

/* ── Breadcrumb ── */

- (void)updateBC {
    for (NSView *v in [self.bc.arrangedSubviews copy]) { [self.bc removeArrangedSubview:v]; [v removeFromSuperview]; }

    NSString *rootName = self.rootPath.lastPathComponent ?: @"Root";
    if (self.browsingArchive) rootName = [NSString stringWithFormat:@"\U0001F4E6 %@", rootName];
    [self.bc addArrangedSubview:[self bcBtn:rootName dir:@"" cur:!self.curDir.length]];

    if (self.curDir.length) {
        NSArray *parts = [self.curDir componentsSeparatedByString:@"/"];
        NSMutableString *acc = [NSMutableString new];
        for (NSUInteger i = 0; i < parts.count; i++) {
            if (acc.length) [acc appendString:@"/"];
            [acc appendString:parts[i]];
            NSTextField *sep = [NSTextField labelWithString:@"\u203A"];
            sep.font = [NSFont systemFontOfSize:11]; sep.textColor = [NSColor colorWithWhite:0.3 alpha:1];
            [self.bc addArrangedSubview:sep];
            [self.bc addArrangedSubview:[self bcBtn:parts[i] dir:[acc copy] cur:i==parts.count-1]];
        }
    }
}

- (NSButton *)bcBtn:(NSString *)t dir:(NSString *)d cur:(BOOL)c {
    NSButton *b = [NSButton buttonWithTitle:t target:self action:@selector(bcNav:)];
    b.bordered = NO;
    b.font = [NSFont systemFontOfSize:11 weight:c ? NSFontWeightSemibold : NSFontWeightRegular];
    b.contentTintColor = c ? NSColor.labelColor : NSColor.secondaryLabelColor;
    objc_setAssociatedObject(b, "d", d, OBJC_ASSOCIATION_RETAIN);
    return b;
}

- (void)bcNav:(NSButton *)s {
    self.curDir = objc_getAssociatedObject(s, "d") ?: @"";
    [self reload];
}

/* ── Status ── */

- (void)updateStatus {
    NSInteger f=0,d=0; uint64_t t=0;
    for (FE *e in self.vis) { if (e.isDir) d++; else { f++; t+=e.size; } }
    NSMutableString *s = [NSMutableString new];
    if (d) [s appendFormat:@"%ld folder%@",(long)d,d==1?@"":@"s"];
    if (d&&f) [s appendString:@",  "];
    if (f) [s appendFormat:@"%ld item%@",(long)f,f==1?@"":@"s"];
    if (t) [s appendFormat:@"  \u00B7  %@",hSz(t)];
    if (self.browsingArchive) [s appendString:@"  \u00B7  archive"];
    self.status.stringValue = s;
}

/* ── Back ── */

- (void)doBack:(id)s {
    (void)s;
    if (!self.curDir.length) return;
    NSString *p = [self.curDir stringByDeletingLastPathComponent];
    self.curDir = ([p isEqualToString:@"/"]||[p isEqualToString:@"."]) ? @"" : p;
    [self reload];
}

/* ── Compress ── */

- (void)doCompress:(id)s {
    (void)s;
    NSOpenPanel *op = [NSOpenPanel openPanel];
    op.canChooseDirectories = NO; op.allowsMultipleSelection = YES;
    if ([op runModal] != NSModalResponseOK || !op.URLs.count) return;
    for (NSURL *u in op.URLs) [self compressPath:u.path];
}

- (void)compressPath:(NSString *)path {
    self.prog.hidden = NO; self.prog.indeterminate = YES; [self.prog startAnimation:nil];
    self.status.stringValue = [NSString stringWithFormat:@"Compressing %@\u2026", path.lastPathComponent];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        FILE *f = fopen(path.UTF8String,"rb");
        if (!f) { dispatch_async(dispatch_get_main_queue(), ^{
            self.prog.hidden=YES; [self.prog stopAnimation:nil];
            self.status.stringValue = @"Error: cannot read file"; }); return; }
        fseek(f,0,SEEK_END); size_t len=(size_t)ftell(f); fseek(f,0,SEEK_SET);
        uint8_t *data=malloc(len); fread(data,1,len,f); fclose(f);

        cc_container *c = cc_container_create(CC_TYPE_RAW);
        cc_container_set_payload(c, data, len);
        cc_container_set_layers(c, CC_LAYER_COMPRESSED);
        uint8_t *out=NULL; size_t ol=0;
        int rc = cc_container_write(c, &out, &ol);
        cc_container_destroy(c); free(data);

        NSString *msg;
        NSString *outPath = [path stringByAppendingString:@".cute"];
        if (rc == CC_OK) {
            FILE *fo=fopen(outPath.UTF8String,"wb");
            if (fo) { fwrite(out,1,ol,fo); fclose(fo); }
            free(out);
            msg = [NSString stringWithFormat:@"%@ \u2192 %@ (%.1f%%)",
                path.lastPathComponent, outPath.lastPathComponent, (double)ol/(double)len*100.0];
        } else { msg = @"Compression failed"; }

        dispatch_async(dispatch_get_main_queue(), ^{
            self.prog.hidden=YES; [self.prog stopAnimation:nil];
            self.status.stringValue = msg;
            /* reveal result */
            if (rc == CC_OK)
                [[NSWorkspace sharedWorkspace] selectFile:outPath inFileViewerRootedAtPath:outPath.stringByDeletingLastPathComponent];
        });
    });
}

/* ── Extract ── */

- (void)doExtract:(id)s {
    (void)s;
    if (self.browsingArchive && self.openArchive) {
        /* extract from open archive */
        NSOpenPanel *dp = [NSOpenPanel openPanel];
        dp.canChooseFiles=NO; dp.canChooseDirectories=YES; dp.canCreateDirectories=YES;
        dp.message = @"Extract to";
        if ([dp runModal] != NSModalResponseOK) return;
        NSString *dest = dp.URL.path;

        self.prog.hidden=NO; self.prog.indeterminate=YES; [self.prog startAnimation:nil];
        self.status.stringValue = @"Extracting\u2026";

        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            int rc = cc_archive_extract_all(self.openArchive, dest.UTF8String);
            dispatch_async(dispatch_get_main_queue(), ^{
                self.prog.hidden=YES; [self.prog stopAnimation:nil];
                if (rc == 0) {
                    self.status.stringValue = [NSString stringWithFormat:@"Extracted to %@", dest.lastPathComponent];
                    [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:dest]];
                } else {
                    self.status.stringValue = @"Extraction failed";
                }
            });
        });
    } else {
        /* pick a .cute file to extract */
        NSOpenPanel *op = [NSOpenPanel openPanel];
        op.message = @"Select file to extract";
        if ([op runModal] != NSModalResponseOK) return;
        NSString *src = op.URL.path;

        NSOpenPanel *dp = [NSOpenPanel openPanel];
        dp.canChooseFiles=NO; dp.canChooseDirectories=YES; dp.canCreateDirectories=YES;
        dp.message = @"Extract to";
        if ([dp runModal] != NSModalResponseOK) return;

        self.prog.hidden=NO; self.prog.indeterminate=YES; [self.prog startAnimation:nil];
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            FILE *f = fopen(src.UTF8String,"rb");
            if (!f) { dispatch_async(dispatch_get_main_queue(), ^{
                self.prog.hidden=YES; self.status.stringValue=@"Error"; }); return; }
            fseek(f,0,SEEK_END); size_t len=(size_t)ftell(f); fseek(f,0,SEEK_SET);
            uint8_t *data=malloc(len); fread(data,1,len,f); fclose(f);
            cc_container *c = cc_container_open(data, len); free(data);
            if (c) {
                size_t pl=0; const void *payload = cc_container_payload(c, &pl);
                NSString *outName = [src.lastPathComponent stringByDeletingPathExtension];
                NSString *outPath = [dp.URL.path stringByAppendingPathComponent:outName];
                FILE *fo=fopen(outPath.UTF8String,"wb");
                if (fo) { fwrite(payload,1,pl,fo); fclose(fo); }
                cc_container_destroy(c);
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.prog.hidden=YES; [self.prog stopAnimation:nil];
                    self.status.stringValue = [NSString stringWithFormat:@"Extracted %@ (%@)", outName, hSz((uint64_t)pl)];
                    [[NSWorkspace sharedWorkspace] selectFile:outPath inFileViewerRootedAtPath:dp.URL.path];
                });
            } else {
                dispatch_async(dispatch_get_main_queue(), ^{
                    self.prog.hidden=YES; self.status.stringValue=@"Not a valid container";
                });
            }
        });
    }
}

/* ── Info ── */

- (void)doInfo:(id)s {
    (void)s;
    FE *e = [self selectedEntry];
    NSString *path = e ? e.diskPath : self.rootPath;
    if (!path) { self.status.stringValue = @"Nothing selected"; return; }

    NSMutableString *info = [NSMutableString new];
    [info appendFormat:@"Name: %@\n", path.lastPathComponent];

    NSFileManager *fm = [NSFileManager defaultManager];
    NSDictionary *attrs = [fm attributesOfItemAtPath:path error:nil];
    if (attrs) {
        uint64_t sz = [attrs[NSFileSize] unsignedLongLongValue];
        [info appendFormat:@"Size: %@\n", hSz(sz)];
        NSDate *mod = attrs[NSFileModificationDate];
        if (mod) {
            NSDateFormatter *df = [[NSDateFormatter alloc] init];
            df.dateStyle = NSDateFormatterMediumStyle; df.timeStyle = NSDateFormatterShortStyle;
            [info appendFormat:@"Modified: %@\n", [df stringFromDate:mod]];
        }

        FILE *f = fopen(path.UTF8String, "rb");
        if (f) {
            uint8_t hdr[64]; size_t rd = fread(hdr,1,64,f); fclose(f);
            cc_content_type type = cc_container_detect(hdr, rd);
            if (type != CC_TYPE_UNKNOWN)
                [info appendFormat:@"Container: %s\n", cc_content_type_name(type)];
        }
    }

    if (e && !e.diskPath && self.browsingArchive) {
        /* entry from archive */
        [info appendFormat:@"Archive path: %@\n", e.path];
        if (e.size) [info appendFormat:@"Original: %@\n", hSz(e.size)];
        if (e.compSize) [info appendFormat:@"Compressed: %@ (%.1f%%)\n", hSz(e.compSize), (double)e.compSize/(double)e.size*100.0];
    }

    NSAlert *a = [[NSAlert alloc] init];
    a.messageText = path.lastPathComponent;
    a.informativeText = info;
    [a addButtonWithTitle:@"OK"];
    if (e && e.diskPath) [a addButtonWithTitle:@"Reveal in Finder"];
    NSModalResponse r = [a runModal];
    if (r == NSAlertSecondButtonReturn && e.diskPath)
        [[NSWorkspace sharedWorkspace] selectFile:e.diskPath inFileViewerRootedAtPath:e.diskPath.stringByDeletingLastPathComponent];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)a { (void)a; return YES; }

@end

/* ── DropWindow ── */

@implementation DropWindow
- (NSDragOperation)draggingEntered:(id<NSDraggingInfo>)s { (void)s; return NSDragOperationCopy; }
- (BOOL)performDragOperation:(id<NSDraggingInfo>)s {
    NSArray<NSURL*> *u = [[s draggingPasteboard] readObjectsForClasses:@[[NSURL class]]
        options:@{NSPasteboardURLReadingFileURLsOnlyKey:@YES}];
    if (!u.count) return NO;
    [(App *)NSApp.delegate openPath:u[0].path];
    return YES;
}
@end

int main(int argc, const char *argv[]) {
    (void)argc;(void)argv;
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        app.activationPolicy = NSApplicationActivationPolicyRegular;
        app.appearance = [NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
        App *d = [[App alloc] init];
        app.delegate = d;
        [app run];
    }
    return 0;
}

#else
#include <stdio.h>
int main(void){fprintf(stderr,"requires macOS\n");return 1;}
#endif
