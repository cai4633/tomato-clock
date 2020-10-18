/// <reference path="./types/index.d.ts" />

interface IAppOption {
  globalData: {
    userInfo?: WechatMiniprogram.UserInfo,
    host?: string,
    app_id?: string,
    app_secret?: string,
    t_app_id?: string,
    t_app_secret?: string,
    AV: any
  }
  userInfoReadyCallback?: WechatMiniprogram.GetUserInfoSuccessCallback,
}



