// pages/home/home.js
import {
  createId
} from '../../common/js/utils';
import {
  getTodoList,
  createTodoItem,
  deleteTodoItem,
  updateTodoItem
} from '../../api/todo';

Page({
  data: {
    createConfirmVisible: false,
    updateConfirmVisible: false,
    todoList: [],
    defaultValue: '',
    selectedId: 0
  },

  onLoad: function (options) {
    getTodoList().then(value => {
      this.setData({
        'todoList': value
      })
    })
  },

  /**
   * 生命周期函数--监听页面初次渲染完成
   */
  onReady: function () {},

  onShow: function () {},

  onHide: function () {},

  onUnload: function () {},

  /**
   * 页面相关事件处理函数--监听用户下拉动作
   */
  onPullDownRefresh: function () {},
  /**
   * 页面上拉触底事件的处理函数
   */
  onReachBottom: function () {},
  onShareAppMessage: function () {},
  showUpdateConfirm() {
    this.setData({
      updateConfirmVisible: true
    })
  },
  hideUpdateConfirm() {
    this.setData({
      updateConfirmVisible: false
    })
  },
  showCreateConfirm(e) {
    this.setData({
      createConfirmVisible: true
    })
  },
  hideCreateConfirm() {
    this.setData({
      createConfirmVisible: false
    })
  },
  cancel(e) {
    this.hideCreateConfirm()
  },
  enter(e) {
    this.hideCreateConfirm()
    createTodoItem(e.detail).then((value) => {
      this.setData({
        'todoList': [value, ...this.data.todoList]
      })
    })
  },
  updateItem(e) {
    this.setData({
      selectedId: e.detail.id,
      defaultValue: e.detail.content
    })
    this.showUpdateConfirm()
  },
  cancelUpdate() {
    this.hideUpdateConfirm()
  },
  enterUpdate(e) {
    const {
      selectedId
    } = this.data
    updateTodoItem(this.data.selectedId, e.detail).then(value => {
      console.log(value);
      this.setData({

        todoList: this.data.todoList.map((item) => (item.id === this.data.selectedId) ? value : item)
      })
    })
    this.hideUpdateConfirm()
  },
  toggleFinished(e) {
    const id = parseInt(e.detail)
    if (!id) { // id 是NaN
      return
    }
    deleteTodoItem(id)
    const list = this.data.todoList.slice()
    const newlist = list.map((item) => item.id === id ? {
      ...item,
      completed: !item.completed
    } : item)
    this.setData({
      todoList: newlist
    })
  }

})