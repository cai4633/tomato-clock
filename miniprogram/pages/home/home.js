// pages/home/home.js
import {
  createId
} from '../../utils/util'
Page({
  data: {
    confirmVisible: false,
    todoList: [{
        id: 1,
        text: 'wishing尼玛1',
        finished: false
      },
      {
        id: 2,
        text: 'wishing尼玛2',
        finished: true
      },
      {
        id: 3,
        text: 'wishing尼玛3',
        finished: true
      },
      {
        id: 4,
        text: 'wishing尼玛4',
        finished: true
      },
      {
        id: 5,
        text: 'wishing尼玛5',
        finished: true
      },
      {
        id: 6,
        text: 'wishing尼玛5',
        finished: true
      },
      {
        id: 7,
        text: 'wishing尼玛5',
        finished: true
      },
      {
        id: 8,
        text: 'wishing尼玛5',
        finished: true
      },
      {
        id: 9,
        text: 'wishing尼玛5',
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
    console.log(this.data.todoList);
    
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
  }

})