// Define the `main` function

const proxyName = "代理模式";

function main(params) {
  if (!params.proxies) return params;
  overwriteRules(params);
  overwriteProxyGroups(params);
  overwriteDns(params);
  return params;
}
//覆写规则
function overwriteRules(params) {
  const customRules = [
    // 在此添加自定义规则, 最高优先级。
    // 为了方便区分，可设置 全局代理模式 或 自定义代理组。
    // 示例1 ：使用 全局代理模式
    //"DOMAIN-SUFFIX,linux.do," + proxyName,
    // 示例2 ：使用 自定义代理组1
    //"DOMAIN-SUFFIX,gstatic.com,自定义代理组1",
    // 示例3 ：使用 自定义代理组2
    //"DOMAIN-SUFFIX,googleapis.com,自定义代理组2",
    "RULE-SET,reject_rules,REJECT-DROP",
    "RULE-SET,direct_rules,DIRECT",    
    "RULE-SET,proxy_rules,GLOBAL",      
    "RULE-SET,BiliBili,哔哩哔哩",
    "RULE-SET,YouTube,YouTube",
  ];


  const rules = [
    ...customRules,
    "RULE-SET,reject,广告拦截",
    "RULE-SET,private_ip,DIRECT,no-resolve",
    "RULE-SET,private_domain,DIRECT",
    "RULE-SET,direct,DIRECT",    
    "RULE-SET,applications,DIRECT",
    "RULE-SET,openai,ChatGPT",
    "RULE-SET,spotify,Spotify",
    "RULE-SET,google_domain,Google",   
    "RULE-SET,telegram_domain,Telegram",    
    "RULE-SET,Microsoft,Microsoft",
    "RULE-SET,twitter_domain,Twitter",    
    "RULE-SET,bahamut_domain,巴哈姆特",
    "RULE-SET,tld-not-cn," + proxyName,    
    "RULE-SET,icloud," + proxyName,
    "RULE-SET,apple," + proxyName,
    "RULE-SET,gfw," + proxyName,
    "RULE-SET,greatfire," + proxyName,
    "RULE-SET,proxy," + proxyName,
    "RULE-SET,google_ip,Google",
    "RULE-SET,telegram_ip,Telegram",
    "RULE-SET,twitter_ip,Twitter",
    "RULE-SET,cncidr,DIRECT",
    "GEOIP,CN,DIRECT,no-resolve",
    "MATCH,漏网之鱼",
  ];
  const ruleProviders = {
	//手动添加规则
    reject_rules: {
      type: "file",
      behavior: "classical",
      format: "text",
      path: "./ruleset/reject_rule.list",    
    },
    direct_rules: {
      type: "file",
      behavior: "classical",
      format: "text",
      path: "./ruleset/direct_rule.list", 
    },
    proxy_rules: {
      type: "file",
      behavior: "classical",
      format: "text",
      path: "./ruleset/proxy_rule.list", 
    },
    
    reject: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
      path: "./ruleset/reject.yaml",
      interval: 86400,
    },
    private_ip: {
      type: "http",
      behavior: "ipcidr",
      url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/private.yaml",
      path: "./ruleset/private_ip.yaml",
      interval: 86400,
    },
    private_domain: {
      type: "http",
      behavior: "domain",
      url: "https://ghp.ci/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.yaml",
      path: "./ruleset/private_domain.yaml",
      interval: 86400,
    },
    icloud: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt",
      path: "./ruleset/icloud.yaml",
      interval: 86400,
    },
    apple: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt",
      path: "./ruleset/apple.yaml",
      interval: 86400,
    },
    google_domain: {
      type: "http",
      behavior: "domain",
      url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/google.yaml",
      path: "./ruleset/google_domain.yaml",
      interval: 86400,
    },
    google_ip: {
      type: "http",
      behavior: "ipcidr",
      url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/google.yaml",
      path: "./ruleset/google_ip.yaml",
      interval: 86400,
    },
    proxy: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
      path: "./ruleset/proxy.yaml",
      interval: 86400,
    },
    openai: {
      type: "http",
      behavior: "classical",
      url: "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/OpenAI/OpenAI.yaml",
      path: "./ruleset/custom/openai.yaml",
      interval: 86400,
    },
    YouTube: {
      type: "http",
      behavior: "classical",
      url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/YouTube/YouTube.yaml",
      path: "./ruleset/custom/YouTube.yaml",
      interval: 86400,
    },
    spotify: {
      type: "http",
      behavior: "classical",
      url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.yaml",
      path: "./ruleset/custom/Spotify.yaml",
      interval: 86400,
    },
    twitter_domain: {
      type: "http",
      behavior: "domain",
      url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/twitter.yaml",
      path: "./ruleset/custom/twitter_domain.yaml",
      interval: 86400,
    },
    twitter_ip: {
      type: "http",
      behavior: "ipcidr",
      url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/twitter.yaml",
      path: "./ruleset/custom/twitter_ip.yaml",
      interval: 86400,
    },
    Microsoft: {
      type: "http",
      behavior: "classical",
      url: "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Microsoft/Microsoft.yaml",
      path: "./ruleset/custom/Microsoft.yaml",
      interval: 86400,
    },
    BiliBili: {
      type: "http",
      behavior: "classical",
      url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/BiliBili/BiliBili.yaml",
      path: "./ruleset/custom/BiliBili.yaml",
      interval: 86400,
    },
    bahamut_domain: {
      type: "http",
      behavior: "domain",
      url: "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/bahamut.yaml",
      path: "./ruleset/custom/bahamut_domain.yaml",
      interval: 86400,
    },
    telegram_domain: {
      type: "http",
      behavior: "domain",
      url: "https://mirror.ghproxy.com/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/telegram.yaml",
      path: "./ruleset/custom/telegram_domain.yaml",
      interval: 86400,
    },
    telegram_ip: {
      type: "http",
      behavior: "ipcidr",
      url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/telegram.yaml",
      path: "./ruleset/custom/telegram_ip.yaml",
      interval: 86400,
    },
    direct: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
      path: "./ruleset/direct.yaml",
      interval: 86400,
    },
    gfw: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt",
      path: "./ruleset/gfw.yaml",
      interval: 86400,
    },
    greatfire: {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/greatfire.txt",
      path: "./ruleset/greatfire.yaml",
      interval: 86400,
    },
    "tld-not-cn": {
      type: "http",
      behavior: "domain",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt",
      path: "./ruleset/tld-not-cn.yaml",
      interval: 86400,
    },    
    cncidr: {
      type: "http",
      behavior: "ipcidr",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
      path: "./ruleset/cncidr.yaml",
      interval: 86400,
    },    
    applications: {
      type: "http",
      behavior: "classical",
      url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt",
      path: "./ruleset/applications.yaml",
      interval: 86400,
    },
  };
  params["rule-providers"] = ruleProviders;
  params["rules"] = rules;
}
//覆写代理组
function overwriteProxyGroups(params) {
  // 添加自用代理
  params.proxies.push(
    //  { name: '1-香港-示例', type: *, server: **, port: *, cipher: **, password: **, udp: true }

  );

  // 所有代理
  const allProxies = params["proxies"].map((e) => e.name);
  // 自动选择代理组，按地区分组选延迟最低
  const autoProxyGroupRegexs = [
    { name: "HK-自动选择", regex: /香港|HK|Hong|🇭🇰/ },
    { name: "TW-自动选择", regex: /台湾|TW|Taiwan|Wan|🇨🇳|🇹🇼/ },
    { name: "SG-自动选择", regex: /新加坡|狮城|SG|Singapore|🇸🇬/ },
    { name: "JP-自动选择", regex: /日本|JP|Japan|🇯🇵/ },
    { name: "US-自动选择", regex: /美国|US|United States|America|🇺🇸/ },
    { name: "其它-自动选择", regex: /^(?!.*(?:🇭🇰|🇯🇵|🇺🇸|🇸🇬|🇨🇳|港|hk|hongkong|台|tw|taiwan|日本|jp|japan|新|sg|singapore|美|us|unitedstates|剩余|到期|主页|官网|游戏|关注|群组|重置)).*/i },
  ];

  const autoProxyGroups = autoProxyGroupRegexs
    .map((item) => ({
      name: item.name,
      type: "url-test",
      url: "http://www.gstatic.com/generate_204",
      interval: 300,
      tolerance: 50,
      proxies: getProxiesByRegex(params, item.regex),
      hidden: true,
    }))
    .filter((item) => item.proxies.length > 0);

  //手工选择代理组
  const manualProxyGroups = [
    { name: "HK-手工选择", regex: /香港|HK|Hong|🇭🇰/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/hk.svg" },
    { name: "TW-手工选择", regex: /台湾|TW|Taiwan|Wan|🇨🇳|🇹🇼/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/tw.svg" },
    { name: "SG-手工选择", regex: /新加坡|狮城|SG|Singapore|🇸🇬/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/sg.svg" },
    { name: "JP-手工选择", regex: /日本|JP|Japan|🇯🇵/, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Japan.png" },
    { name: "US-手工选择", regex: /美国|US|United States|America|🇺🇸/, icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/flags/us.svg" },
    { name: "其它-手动选择", regex: /^(?!.*(?:🇭🇰|🇯🇵|🇺🇸|🇸🇬|🇨🇳|港|hk|hongkong|台|tw|taiwan|日本|jp|japan|新|sg|singapore|美|us|unitedstates|剩余|到期|主页|官网|游戏|关注|群组|重置)).*/i, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Available.png" },
  ];

  const manualProxyGroupsConfig = manualProxyGroups
    .map((item) => ({
      name: item.name,
      type: "select",
      proxies: getManualProxiesByRegex(params, item.regex),
      icon: item.icon,
      hidden: false,
    }))
    .filter((item) => item.proxies.length > 0);

  const groups = [
    {
      name: proxyName,
      type: "select",
      url: "http://www.gstatic.com/generate_204",
      icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png",
      proxies: [
        "自动选择",
        "手动选择",
        "负载均衡(散列)",
        "负载均衡(轮询)",
        "DIRECT",
      ],
    },
    {
      name: "手动选择",
      type: "select",
      icon: "https://fastly.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png",
      proxies: allProxies,
    },
    {
      name: "自动选择",
      type: "select",
      icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png",
      proxies: ["ALL-自动选择"],
    },
    {
      name: "负载均衡(散列)",
      type: "load-balance",
      url: "http://www.gstatic.com/generate_204",
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/balance.svg",
      "exclude-filter": "(?i)GB|Traffic|Expire|Premium|频道|订阅|ISP|流量|到期|重置|官网|群组",
      interval: 300,
      "max-failed-times": 3,
      strategy: "consistent-hashing",
      lazy: true,
      proxies: allProxies,
    },
    {
      name: "负载均衡(轮询)",
      type: "load-balance",
      url: "http://www.gstatic.com/generate_204",
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/merry_go.svg",
      "exclude-filter": "(?i)GB|Traffic|Expire|Premium|频道|订阅|ISP|流量|到期|重置|官网|群组",
      interval: 300,
      "max-failed-times": 3,
      strategy: "round-robin",
      lazy: true,
      proxies: allProxies,
    },
    {
      name: "ALL-自动选择",
      type: "url-test",
      url: "http://www.gstatic.com/generate_204",
      interval: 300,
      tolerance: 50,
      proxies: allProxies,
      hidden: true,
    },
    {
      name: "Telegram",
      type: "select",
      proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择", "其它-手动选择"],
      // "include-all": true,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/telegram.svg"
    },
    {
      name: "Google",
      type: "select",
      proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择", "其它-手动选择"],
      // "include-all": true,
      icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Google_Search.png"
    },
    {
      name: "ChatGPT",
      type: "select",
      proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择", "其它-手动选择"],
      // "include-all": true,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/chatgpt.svg"
    },
    {
      name: "YouTube",
      type: "select",
      proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择", "其它-手动选择"],
      // "include-all": true,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/youtube.svg"
    },
    {
      name: "Spotify",
      type: "select",
      proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择", "其它-手动选择"],
      // "include-all": true,
      icon: "https://storage.googleapis.com/spotifynewsroom-jp.appspot.com/1/2020/12/Spotify_Icon_CMYK_Green.png"
    },
    {
      name: "Twitter",
      type: "select",
      proxies: [proxyName, "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择", "其它-手动选择"],
      // "include-all": true,
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/twitter.svg"
    },
    {
      name: "Microsoft",
      type: "select",
      proxies: ["DIRECT", proxyName],
      icon: "https://www.clashverge.dev/assets/icons/microsoft.svg"
    },
    {
      name: "哔哩哔哩",
      type: "select",
      proxies: ["DIRECT", "HK-自动选择", "TW-自动选择", "HK-手工选择", "TW-手工选择", "其它-手动选择"],
      // "include-all": true,
      icon: "https://img.z4a.net/images/2024/11/25/bilibili__aigei_com.png"
    },
    {
      name: "巴哈姆特",
      type: "select",
      proxies: ["HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择", "其它-手动选择", proxyName, "手动选择", "DIRECT"],
      // "include-all": true,
      icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Bahamut.png"
    },
    {
      name: "漏网之鱼",
      type: "select",
      proxies: ["DIRECT", proxyName, "手动选择"],
      icon: "https://fastly.jsdelivr.net/gh/clash-verge-rev/clash-verge-rev.github.io@main/docs/assets/icons/fish.svg"
    },
    {
      name: "广告拦截",
      type: "select",
      proxies: ["REJECT", "DIRECT", proxyName],
      icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/AdBlack.png"
    },
  ];

  autoProxyGroups.length &&
    groups[2].proxies.unshift(...autoProxyGroups.map((item) => item.name));
  groups.push(...autoProxyGroups);
  groups.push(...manualProxyGroupsConfig);
  params["proxy-groups"] = groups;

  // 添加 GLOBAL 代理组到最后
  const globalGroup = {
    name: "GLOBAL",
    type: "select",
    proxies: [proxyName, "手动选择", "自动选择", "负载均衡(散列)", "负载均衡(轮询)", "Telegram", "Google", "ChatGPT", "YouTube", "Spotify", "Twitter", "Microsoft", "哔哩哔哩", "巴哈姆特", "漏网之鱼", "广告拦截", "HK-自动选择", "TW-自动选择", "SG-自动选择", "JP-自动选择", "US-自动选择", "其它-自动选择", "HK-手工选择", "TW-手工选择", "SG-手工选择", "JP-手工选择", "US-手工选择", "其它-手动选择"],
    "include-all": true,
    icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png",
    "exclude-filter": "(?i)GB|Traffic|Expire|Premium|频道|订阅|ISP|流量|到期|重置|官网|群组",
  };

  // 在数组末尾插入 GLOBAL
  groups.push(globalGroup);

  params["proxy-groups"] = groups;
}
//防止dns泄露
function overwriteDns(params) {
  const cnDnsList = [
    "https://223.5.5.5/dns-query",
    "https://1.12.12.12/dns-query",
  ];
  const trustDnsList = [
    'quic://dns.cooluc.com',
    "https://1.0.0.1/dns-query",
    "https://1.1.1.1/dns-query",
  ];

  const dnsOptions = {
    enable: true,
    "prefer-h3": true, // 如果DNS服务器支持DoH3会优先使用h3
    "default-nameserver": cnDnsList, // 用于解析其他DNS服务器、和节点的域名, 必须为IP, 可为加密DNS。注意这个只用来解析节点和其他的dns，其他网络请求不归他管
    nameserver: trustDnsList, // 其他网络请求都归他管

    // 这个用于覆盖上面的 nameserver
    "nameserver-policy": {
      //[combinedUrls]: notionDns,
      "geosite:cn": cnDnsList,
      "geosite:geolocation-!cn": trustDnsList,
      // 如果你有一些内网使用的DNS，应该定义在这里，多个域名用英文逗号分割
      // '+.公司域名.com, www.4399.com, +.baidu.com': '10.0.0.1'
    },
    fallback: trustDnsList,
    "fallback-filter": {
      geoip: true,
      //除了 geoip-code 配置的国家 IP, 其他的 IP 结果会被视为污染 geoip-code 配置的国家的结果会直接采用，否则将采用 fallback结果
      "geoip-code": "CN",
      //geosite 列表的内容被视为已污染，匹配到 geosite 的域名，将只使用 fallback解析，不去使用 nameserver
      geosite: ["gfw"],
      ipcidr: ["240.0.0.0/4"],
      domain: ["+.google.com", "+.facebook.com", "+.youtube.com"],
    },
  };

  // GitHub加速前缀
  const githubPrefix = "https://fastgh.lainbo.com/";

  // GEO数据GitHub资源原始下载地址
  const rawGeoxURLs = {
    geoip:
      "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat",
    geosite:
      "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
    mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb",
  };

  // 生成带有加速前缀的GEO数据资源对象
  const accelURLs = Object.fromEntries(
    Object.entries(rawGeoxURLs).map(([key, githubUrl]) => [
      key,
      `${githubPrefix}${githubUrl}`,
    ])
  );

  const otherOptions = {
    "unified-delay": true,
    "tcp-concurrent": true,
    profile: {
      "store-selected": true,
      "store-fake-ip": true,
    },
    sniffer: {
      enable: true,
      sniff: {
        TLS: {
          ports: [443, 8443],
        },
        HTTP: {
          ports: [80, "8080-8880"],
          "override-destination": true,
        },
      },
    },
    "geodata-mode": true,
    "geox-url": accelURLs,
  };

  params.dns = { ...params.dns, ...dnsOptions };
  Object.keys(otherOptions).forEach((key) => {
    params[key] = otherOptions[key];
  });
}

function getProxiesByRegex(params, regex) {
  const matchedProxies = params.proxies.filter((e) => regex.test(e.name)).map((e) => e.name);
  return matchedProxies.length > 0 ? matchedProxies : ["手动选择"];
}

function getManualProxiesByRegex(params, regex) {
  const matchedProxies = params.proxies.filter((e) => regex.test(e.name)).map((e) => e.name);
  return matchedProxies.length > 0 ? matchedProxies : ["DIRECT", "手动选择", proxyName];
}
