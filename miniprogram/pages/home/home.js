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

const {
  AV
} = getApp().globalData
Page({
  data: {
    createConfirmVisible: false,
    updateConfirmVisible: false,
    todoList: [],
    defaultValue: '',
    selectedId: 0,
  },

  onLoad: function (options) {
    getTodoList().then(res => {
      this.setData({
        'todoList': res
      })
    })
  },

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
    createTodoItem(e.detail).then((value) => {
      this.setData({
        'todoList': [value, ...this.data.todoList]
      })
      this.hideCreateConfirm()
    }).catch((err) => {
      console.log(err);
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
    updateTodoItem(this.data.selectedId, e.detail).then(res => {
      this.setData({
        todoList: this.data.todoList.map((item) => (item.objectId === this.data.selectedId) ? res : item)
      })
      this.hideUpdateConfirm()
    }).catch((err) => {
      console.log(err);
    })
  },

  toggleFinished(e) {
    const id = e.detail
    if (!id) {
      return
    }
    deleteTodoItem(id)
    const list = this.data.todoList.slice()
    const newlist = list.map((item) => item.objectId === id ? {
      ...item,
      completed: !item.completed
    } : item)
    this.setData({
      todoList: newlist
    })
  }

})