// itssssdiscotime - flashes random colors over the whole screen.
// The "Enable Disco" switch in Settings turns it on and off without a respring.

#import <UIKit/UIKit.h>

#define PREFS_DOMAIN CFSTR("com.techieben.itssssdiscotime")
#define PREFS_CHANGED CFSTR("com.techieben.itssssdiscotime/prefschanged")

static BOOL discoEnabled = YES;
static BOOL springBoardReady = NO;
static UIWindow *discoWindow = nil;
static NSTimer *discoTimer = nil;

static void loadPrefs(void) {
    // CFPreferences works on every iOS version; reading the .plist file directly
    // can return stale values on iOS 8+ because cfprefsd caches them.
    CFPreferencesAppSynchronize(PREFS_DOMAIN);
    CFPropertyListRef value = CFPreferencesCopyAppValue(CFSTR("enabled"), PREFS_DOMAIN);
    discoEnabled = value ? [(__bridge id)value boolValue] : YES;
    if (value) CFRelease(value);
}

// NSTimer needs an object target, so this small class does the color changes.
@interface DiscoTicker : NSObject
+ (instancetype)shared;
- (void)tick:(NSTimer *)timer;
@end

@implementation DiscoTicker
+ (instancetype)shared {
    static DiscoTicker *ticker = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ ticker = [DiscoTicker new]; });
    return ticker;
}

- (void)tick:(NSTimer *)timer {
    CGFloat r = arc4random_uniform(256) / 255.0;
    CGFloat g = arc4random_uniform(256) / 255.0;
    CGFloat b = arc4random_uniform(256) / 255.0;
    discoWindow.backgroundColor = [UIColor colorWithRed:r green:g blue:b alpha:1.0];
}
@end

static void startDisco(void) {
    if (!discoWindow) {
        // A window of our own sits above everything and covers the whole screen,
        // so we don't depend on SpringBoard's keyWindow existing yet.
        discoWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        discoWindow.windowLevel = UIWindowLevelStatusBar + 100;
        discoWindow.userInteractionEnabled = NO; // touches pass through to the screen below
        discoWindow.alpha = 0.3;
    }
    discoWindow.hidden = NO;

    if (!discoTimer) {
        discoTimer = [NSTimer scheduledTimerWithTimeInterval:0.1
                                                      target:[DiscoTicker shared]
                                                    selector:@selector(tick:)
                                                    userInfo:nil
                                                     repeats:YES];
    }
}

static void stopDisco(void) {
    // Stop the timer completely when off so it doesn't drain the battery.
    [discoTimer invalidate];
    discoTimer = nil;
    discoWindow.hidden = YES;
}

static void applyPrefs(void) {
    if (!springBoardReady) return;
    if (discoEnabled) {
        startDisco();
    } else {
        stopDisco();
    }
}

static void prefsChanged(CFNotificationCenterRef center, void *observer, CFStringRef name,
                         const void *object, CFDictionaryRef userInfo) {
    loadPrefs();
    dispatch_async(dispatch_get_main_queue(), ^{ applyPrefs(); });
}

%hook SpringBoard

- (void)applicationDidFinishLaunching:(id)application {
    %orig;
    springBoardReady = YES;
    dispatch_async(dispatch_get_main_queue(), ^{ applyPrefs(); });
}

%end

%ctor {
    loadPrefs();
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                    NULL,
                                    prefsChanged,
                                    PREFS_CHANGED,
                                    NULL,
                                    CFNotificationSuspensionBehaviorCoalesce);
}
