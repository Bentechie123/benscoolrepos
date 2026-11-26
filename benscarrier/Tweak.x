// Ben's Carrier - replace the carrier name (and "No Service" / "Searching...")
// in the status bar with your own text, with an optional logo in front.
// Supports iOS 5 through 10.

#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#define PREFS_DOMAIN CFSTR("com.techieben.benscarrier")
#define PREFS_PATH @"/var/mobile/Library/Preferences/com.techieben.benscarrier.plist"
#define PREFS_CHANGED CFSTR("com.techieben.benscarrier/prefschanged")

// The status bar item that draws the carrier name. Private UIKit class,
// present from iOS 5 through iOS 10; it stores its text in the _serviceString ivar.
@interface UIStatusBarServiceItemView : UIView
@end

static BOOL tweakEnabled = YES;
static NSString *customName = nil;
static NSString *logo = nil;

// SpringBoard can read prefs with CFPreferences. Sandboxed apps on iOS 8+
// can't, so fall back to reading the plist file directly.
static id prefValue(NSString *key, NSDictionary *fileDict) {
    CFPropertyListRef value = CFPreferencesCopyAppValue((__bridge CFStringRef)key, PREFS_DOMAIN);
    if (value) return (__bridge_transfer id)value;
    return fileDict[key];
}

static void loadPrefs(void) {
    CFPreferencesAppSynchronize(PREFS_DOMAIN);
    NSDictionary *fileDict = [NSDictionary dictionaryWithContentsOfFile:PREFS_PATH];

    id enabled = prefValue(@"enabled", fileDict);
    tweakEnabled = enabled ? [enabled boolValue] : YES;

    id name = prefValue(@"carrierName", fileDict);
    NSString *trimmed = [name isKindOfClass:[NSString class]]
        ? [name stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]] : nil;
    customName = trimmed.length ? [trimmed copy] : nil;

    id chosenLogo = prefValue(@"logo", fileDict);
    logo = ([chosenLogo isKindOfClass:[NSString class]] && [chosenLogo length]) ? [chosenLogo copy] : nil;
}

static void prefsChanged(CFNotificationCenterRef center, void *observer, CFStringRef name,
                         const void *object, CFDictionaryRef userInfo) {
    loadPrefs();
}

// What the status bar should show, given the text UIKit wanted to show.
static NSString *displayString(NSString *original) {
    NSString *text = customName ?: original ?: @"";
    if (logo) {
        return text.length ? [NSString stringWithFormat:@"%@ %@", logo, text] : logo;
    }
    return text;
}

// Associated-object keys: remember UIKit's own text and the text we put in,
// so repeated updates don't stack logos or lose the real carrier name.
static char kOriginalKey;
static char kOutputKey;

%hook UIStatusBarServiceItemView

- (BOOL)updateForNewData:(id)data actions:(int)actions {
    BOOL changed = %orig;

    Ivar ivar = class_getInstanceVariable([self class], "_serviceString");
    if (!ivar) return changed; // unknown iOS layout: leave the status bar alone

    NSString *current = object_getIvar(self, ivar);
    NSString *lastOutput = objc_getAssociatedObject(self, &kOutputKey);
    NSString *original;
    if (lastOutput && [current isEqual:lastOutput]) {
        original = objc_getAssociatedObject(self, &kOriginalKey);
    } else {
        original = current;
        objc_setAssociatedObject(self, &kOriginalKey, original, OBJC_ASSOCIATION_COPY_NONATOMIC);
    }

    NSString *wanted = (tweakEnabled && (customName || logo)) ? displayString(original) : original;
    if (!wanted || [wanted isEqual:current]) return changed;

    // UIKit owns this ivar with manual retain/release: retain the new string
    // for it and release the one it held.
    object_setIvar(self, ivar, (__bridge id)CFBridgingRetain([wanted copy]));
    if (current) CFRelease((__bridge CFTypeRef)current);

    objc_setAssociatedObject(self, &kOutputKey, wanted, OBJC_ASSOCIATION_COPY_NONATOMIC);
    return YES; // tells the status bar to redraw this item
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
