import { TodoListItem, TomatoItem } from '../../typings/types/index';

const { AV } = getApp().globalData

function getAllTomatoes() { //最近一周
  const query = new AV.Query('Tomatoes')
  return query.descending('createdAt').limit(15).find().then((tomatoes: TomatoItem[]) => {
    return tomatoes.map((tomato) => tomato.toJSON())
  })
}

function getAllCompleted() {
  const todoQuery = new AV.Query('Todos')
  const tomatoQuery = new AV.Query('Tomatoes')
  todoQuery.equalTo('completed', true).descending('createdAt').limit(10)
  tomatoQuery.equalTo('aborted', false).descending('createdAt').limit(10)
  return Promise.all([todoQuery.find(), tomatoQuery.find()]).then((response: [TodoListItem[], TomatoItem[]]) => [...response[0].map(item => item.toJSON()), ...response[1].map(item => item.toJSON())])
}

export { getAllTomatoes, getAllCompleted }