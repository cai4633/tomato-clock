import {
  http
} from '../../api/http'
Page({
  data: {
    tabIndex: 1,
    taskList: {}
  },
  onLoad(){
    http.get('/tomatoes', {
      is_group: "yes"
    }).then((res) => {
      this.setData({
        taskList: res.data.resources
      })
    })
  },
  onShow() {},
  gotoTomato() {
    this.setData({
      tabIndex: 1
    })
    http.get('/tomatoes', {
      is_group: "yes"
    }).then((res) => {
      this.setData({
        taskList: res.data.resources
      })
    })
  },
  gotoTodo() {
    this.setData({
      tabIndex: 2
    })
    http.get('/todos', {
      is_group: "yes"
    }).then((res) => {
      this.setData({
        taskList: res.data.resources
      })
    })
  }
})