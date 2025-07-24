// 引入加密函式庫
const crypto = require('crypto');

// 這個變數用來在 Vercel 環境中快取 Token，避免每次都重新登入
let cachedToken = {
  value: null,
  expiresAt: 0,
};

// --- 這是獲取 Token 的核心函式 ---
async function getValidToken() {
  // 如果快取的 Token 仍然有效 (預留 60 秒緩衝)，直接回傳
  if (cachedToken.value && Date.now() < cachedToken.expiresAt - 60000) {
    return cachedToken.value;
  }

  // 從 Vercel 環境變數中讀取您的憑證
  const username = process.env.LOGIN_USERNAME;
  const password = process.env.LOGIN_PASSWORD;

  if (!username || !password) {
    throw new Error('Username or Password is not set in Vercel Environment Variables.');
  }

  // 1. 對您的【原始密碼】進行標準 MD5 加密
  const standardHash = crypto.createHash('md5').update(password).digest('hex');

  // 2. 應用我們逆向工程發現的【獨特重排演算法】
  const finalPassword = standardHash.slice(-6) + standardHash.slice(6, 26) + standardHash.slice(0, 6);

  const authUrl = 'http://39.108.191.53:8089/api/v1/login/login';

  const response = await fetch(authUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: username,
      password: finalPassword,
    }),
  });

  const data = await response.json();

  if (!response.ok || !data.data || !data.data.token) {
    throw new Error(`Failed to fetch token: ${data.msg || 'Unknown error'}`);
  }

  const accessToken = data.data.token;
  const expiresIn = data.data.expires_in; // 這是秒

  // 更新快取
  cachedToken.value = accessToken;
  cachedToken.expiresAt = Date.now() + expiresIn * 1000; // 將秒轉為毫秒級的時間戳

  return accessToken;
}

// --- 這是我們主要的代理處理函式 ---
module.exports = async (req, res) => {
  try {
    // 1. 自動獲取一個有效的 X-Token
    const xToken = await getValidToken();
    const appKey = process.env.APP_KEY; // 從環境變數讀取 App Key

    // 2. 組合最終要請求的目標 API URL
    const targetApiHost = 'http://39.108.191.53:8089';
    // 從前端請求的 URL 中提取出查詢參數部分
    const queryString = req.url.split('?')[1] || '';
    const targetUrl = `${targetApiHost}/api/v1/device/hisdps?${queryString}`;

    // 3. 準備請求
    const fetchOptions = {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'App-Key': appKey,
        'X-Token': xToken,
      },
    };

    // 4. 發送請求到真正的 API
    const targetResponse = await fetch(targetUrl, fetchOptions);
    const responseData = await targetResponse.json();

    // 5. 將從 API 收到的結果，原封不動地回傳給前端網頁
    res.status(targetResponse.status).json(responseData);

  } catch (error) {
    // 如果過程中發生任何錯誤，回傳 500 錯誤
    console.error('Proxy handler error:', error);
    res.status(500).json({ error: 'An error occurred in the proxy handler.', details: error.message });
  }
};
