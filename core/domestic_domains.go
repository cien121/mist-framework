package core

// Domestic domain suffix list for split routing (v1).
//
// Match semantics: a query domain D is domestic if D == entry or
// D ends with "."+entry (case-insensitive; the engine lowercases
// QNAME before matching). Additionally, ANY domain ending in ".cn"
// is domestic by rule (covers .com.cn/.gov.cn/.edu.cn and the long
// tail) and needs no list entry.
//
// What this list is: well-known domestic services under non-.cn
// suffixes. It deliberately contains NO global platform that chan
// uses through the tunnel (google, youtube, facebook, instagram,
// whatsapp, telegram, x, netflix, apple, microsoft, ...): a domain
// wrongly listed as domestic would route that traffic direct and
// leak it outside the tunnel. The safe failure direction is
// "unknown -> tunnel", so this list stays conservative: when in
// doubt, leave it out.
//
// v1 mechanism note: split routing is domain-driven. The data path
// does not consult a CN CIDR table (none is embedded in v1): an IP
// routes direct if it was learned from a domestic-domain local
// resolution (see learnedIPs), or if it is private/reserved/loopback.
// Literal-IP flows with no prior domestic resolution default to the
// tunnel. A full CN CIDR table is a later enhancement, not a v1
// requirement: the current mechanism already covers the overwhelming
// majority of app traffic, which connects by domain.
var domesticDomainSuffixes = []string{
	"163.com",
	"126.com",
	"188.com",
	"360.com",
	"alibaba.com",
	"alipay.com",
	"aliyun.com",
	"baidu.com",
	"baike.com",
	"bilibili.com",
	"cctv.com",
	"cnblogs.com",
	"csdn.net",
	"ctrip.com",
	"damai.com",
	"dianping.com",
	"didi.com",
	"dingtalk.com",
	"douyin.com",
	"douyu.com",
	"ele.me",
	"fliggy.com",
	"gaode.com",
	"gitee.com",
	"hellobike.com",
	"honor.com",
	"huawei.com",
	"huya.com",
	"iqiyi.com",
	"jd.com",
	"juejin.cn",
	"kaola.com",
	"kuaishou.com",
	"meituan.com",
	"mi.com",
	"mgtv.com",
	"oppo.com",
	"oschina.net",
	"pinduoduo.com",
	"pptv.com",
	"qunar.com",
	"qq.com",
	"segmentfault.com",
	"sina.com",
	"sina.com.cn",
	"sohu.com",
	"sogou.com",
	"taobao.com",
	"tmall.com",
	"tencent.com",
	"toutiao.com",
	"tudou.com",
	"vivo.com",
	"weibo.com",
	"weibo.cn",
	"wechat.com",
	"xianyu.com",
	"xiaohongshu.com",
	"xinhuanet.com",
	"xunlei.com",
	"yanxuan.com",
	"youku.com",
	"zhihu.com",
}
