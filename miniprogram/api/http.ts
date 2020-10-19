interface PromiseValueType {
  data: string | WechatMiniprogram.IAnyObject
  header: WechatMiniprogram.IAnyObject
  statusCode: number
  errMsg: string
}

const { host } = getApp().globalData
const _http = (method: WechatMiniprogram.RequestOption['method'], path: string, data: any) => {
  return new Promise<PromiseValueType>((resolve, reject) => {
    wx.request({
      method,
      url: `${host}${path}`,
      data,
      success: (res: WechatMiniprogram.RequestSuccessCallbackResult) => {
        const {
          statusCode
        } = res
        console.log(res);

        if (statusCode >= 400) {
          if (statusCode === 401) {
            wx.redirectTo({
              url: '/pages/login/login',
            })
          }
          reject(res)
        } else {
          resolve(res)
        }
      },
      fail(error) {
        wx.showToast({
          title: '请求失败',
        })
        reject(error)
      }
    })
  }).catch((e: any) => {
    console.log(e);
  })
}

export const http = {
  get: (path: string, param?: any) => _http('GET', path, param),
  post: (path: string, data?: any) => _http('POST', path, data),
  put: (path: string, data: any) => _http('PUT', path, data),
  delete: (path: string, data: any) => _http('DELETE', path, data),
}