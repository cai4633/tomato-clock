import {
  getToken
} from '../../api/getToken'

const {
  app_id,
  app_secret,
  AV
} = getApp().globalData
Page({
  login(e) {
    AV.User.loginWithMiniApp().then(user => {
      this.saveMessage(user['_sessionToken'])
      wx.reLaunch({
        url: '/pages/home/home',
      })
    }).catch(console.error);
  },
  saveMessage(token) {
    wx.setStorageSync('_sessionToken', token)
  },

  onLoad: function (options) {},

})