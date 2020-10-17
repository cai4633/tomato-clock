// pages/login/login.js
import {
  http
} from '../../api/http'

const {
  app_id,
  app_secret
} = getApp().globalData
Page({
  data: {

  },

  login(e) {
    const {
      iv,
      encryptedData,
    } = e.detail
    this.wxLogin(iv, encryptedData)
  },

  wxLogin(iv, encryptedData) {
    wx.login({
      success: (res) => {
        const data = {
          code: res.code,
          encrypted_data: encryptedData,
          iv,
          app_id,
          app_secret
        }
        http.post('/sign_in/mini_program_user', data).then((res) => {
          if (res) {
            this.saveMessage(res.data.resource, res.header['X-token'])
            wx.reLaunch({
              url: '/pages/home/home',
            })
          }
        })
      }
    })
  },

  saveMessage(data, token) {
    wx.setStorageSync('me', data)
    wx.setStorageSync('X-token', token)
  },

  onLoad: function (options) {},

  /**
   * 生命周期函数--监听页面初次渲染完成
   */
  onReady: function () {

  },

  /**
   * 生命周期函数--监听页面显示
   */
  onShow: function () {},

  /**
   * 生命周期函数--监听页面隐藏
   */
  onHide: function () {

  },

  /**
   * 生命周期函数--监听页面卸载
   */
  onUnload: function () {

  },

  /**
   * 页面相关事件处理函数--监听用户下拉动作
   */
  onPullDownRefresh: function () {

  },

  /**
   * 页面上拉触底事件的处理函数
   */
  onReachBottom: function () {

  },

  /**
   * 用户点击右上角分享
   */
  onShareAppMessage: function () {

  }
})