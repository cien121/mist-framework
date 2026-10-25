package core

// Ad/tracker domain seed list for DNS-layer ad blocking (v1).
//
// Match semantics: same suffix rule as domestic domains (exact or
// "."+entry suffix, case-insensitive). A match returns a null answer
// (A -> 0.0.0.0, AAAA -> ::, other types -> NOERROR with no answers)
// instead of resolving.
//
// Curation rule (conservative seed): only pure ad-serving networks
// and unambiguous third-party trackers. Deliberately excluded, even
// though blocklists elsewhere include them: social SDK domains
// (facebook.net, connect.facebook.net), analytics SDKs apps may
// depend on (umeng.com, segment.io, mixpanel.com, amplitude.com),
// push infra (jpush, getui), any CDN that also serves content
// (alicdn.com, baidustatic.com), and every content domain itself
// (youtube.com, googlevideo.com, facebook.com, ...). A false
// positive here looks exactly like a tunnel failure to the user,
// so when in doubt this list omits rather than includes. It is a
// seed: coverage grows with follow-up updates, and the Weave
// settings toggle disables it instantly if anything breaks.
var adblockDomainSuffixes = []string{
	// Global ad networks / exchanges / trackers.
	"adcash.com",
	"adcolony.com",
	"adroll.com",
	"adsafeprotected.com",
	"adsrvr.org",
	"adsterra.com",
	"adservice.google.com",
	"adtechus.com",
	"amazon-adsystem.com",
	"applovin.com",
	"bidswitch.net",
	"casalemedia.com",
	"chartboost.com",
	"contextweb.com",
	"criteo.com",
	"criteo.net",
	"doubleclick.net",
	"exoclick.com",
	"googleadservices.com",
	"google-analytics.com",
	"googlesyndication.com",
	"googletagmanager.com",
	"inmobi.com",
	"ironsource.com",
	"juicyads.com",
	"lijit.com",
	"mathtag.com",
	"moatads.com",
	"openx.net",
	"outbrain.com",
	"popads.net",
	"popcash.net",
	"propellerads.com",
	"pubmatic.com",
	"quantserve.com",
	"rubiconproject.com",
	"scorecardresearch.com",
	"sovrn.com",
	"taboola.com",
	"tapjoy.com",
	"vungle.com",
	// Domestic ad networks / exchanges (ad-serving only).
	"ad.qq.com",
	"ad.sina.com.cn",
	"ad.xiaomi.com",
	"alimama.com",
	"cpro.baidu.com",
	"gdt.qq.com",
	"hm.baidu.com",
	"pos.baidu.com",
	"sax.sina.com.cn",
	"tanx.com",
	"union.360.cn",
	"union.sogou.com",
}
