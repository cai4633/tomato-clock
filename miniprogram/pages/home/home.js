// pages/home/home.js
import {
  createId
} from '../../utils/util'
Page({
  data: {
    confirmVisible: false,
    todoList: [{
        id: 1,
        text: '我今天干了啥1,我今天干了啥1,我今天干了啥1,我今天干了啥1,我今天干了啥1我今天干了啥1我今天干了啥1我今天干了啥1我今天干了啥1我今天干了啥1我今天干了啥1',
        finished: false
      },
      {
        id: 2,
        text: '我今天干了啥2',
        finished: true
      },
      {
        id: 3,
        text: '我今天干了啥3',
        finished: true
      },
      {
        id: 4,
        text: '我今天干了啥4',
        finished: true
      },
      {
        id: 5,
        text: '我今天干了啥5',
        finished: true
      },
      {
        id: 6,
        text: '我今天干了啥5',
        finished: true
      },
      {
        id: 7,
        text: '我今天干了啥5',
        finished: true
      },
      {
        id: 8,
        text: '我今天干了啥5',
        finished: true
      },
      {
        id: 9,
        text: '我今天干了啥5',
        finished: true
      },
    ]
  },

  onLoad: function (options) {

  },

  /**
   * 生命周期函数--监听页面初次渲染完成
   */
  onReady: function () {

  },

  /**
   * 生命周期函数--监听页面显示
   */
  onShow: function () {

  },

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

  },
  showConfirm(e) {
    this.setData({
      confirmVisible: true
    })
  },
  hideConfirm() {
    this.setData({
      confirmVisible: false
    })
  },
  cancel(e) {
    this.hideConfirm()
  },
  enter(e) {
    this.hideConfirm()
    this.addlist(e.detail)
  },
  addlist(content) {
    const list = this.data.todoList.slice()
    const newItem = {
      id: createId(this.data.todoList),
      text: content,
      finished: false
    }
    this.setData({
      todoList: [...list, newItem]
    })
  },
  toggleFinished(e) {
    const id = parseInt(e.detail)
    if (!id) { // id 是NaN
      return
    }
    const list = this.data.todoList.slice()
    const newlist = list.map((item) => item.id === id ? {
      ...item,
      finished: !item.finished
    } : item)
    this.setData({
      todoList: newlist
    })
  }

})