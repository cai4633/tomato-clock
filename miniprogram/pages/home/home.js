// pages/home/home.js
import {
  createId
} from '../../common/js/utils';
import {
  getTodoList,
  createTodoItem,
  deleteTodoItem
} from '../../api/todo';

Page({
  data: {
    confirmVisible: false,
    todoList: []
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

  showCreateConfirm(e) {
    this.setData({
      confirmVisible: true
    })
  },
  hideCreateConfirm() {
    this.setData({
      confirmVisible: false
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
  updateItem(e){
    
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