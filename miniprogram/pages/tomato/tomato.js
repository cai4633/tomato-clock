// pages/tomato/tomato.js
import {
  padLeft
} from '../../common/js/utils';
Page({
  timer: null,
  data: {
    totalTime: 5,
    remaining: 5,
    time: '',
    isPause: true,
    isStop: false,
    visible: false
  },

  formatTime(remaining) {
    this.setData({
      time: padLeft(remaining / 60 | 0) + ':' + padLeft(remaining % 60)
    })
  },

  timeStart() {
    this.formatTime(this.data.remaining) //init 显示时间
    this.setData({
      isPause: false,
      isStop: false
    })
    if (!this.timer) { //无计时器,添加计时器
      this.timer = setInterval(() => {
        const {
          isPause,
          remaining
        } = this.data
        if (!isPause) {
          this.setData({
            remaining: remaining - 1,
          })
          this.formatTime(this.data.remaining)
          if (remaining - 1 <= 0) { //倒计时结束
            this.setData({
              remaining: this.data.totalTime,
              isPause: true,
              isStop: true
            })
            clearInterval(this.timer)
            this.timer = null
          }
        }
      }, 1000)
    }
  },

  timePause() { //暂停
    this.setData({
      isPause: true
    })
  },
  abandon() {
    this.setData({
      visible: true
    })
  },
  cancel() {
    this.setData({
      visible: false
    })
  },
  enter() {
    this.setData({
      visible: false
    })
  },


  onLoad: function (options) {

  },

  onReady: function () {
    this.timeStart()
  },

  onShow: function () {

  },

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