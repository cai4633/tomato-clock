import { TodoListItem, TomatoItem } from '../../typings/types/index';
import {
  secureCheck
} from './cloudfunc'
const { AV } = getApp().globalData
const getTodoList = () => {
  return new AV.Query('Todos').descending('createdAt')
    .find()
    .then((todos: TodoListItem[]) => {
      return todos.map((todo) => todo.toJSON())
    })
    .catch(console.error);
}

const createTodoItem = (description: string) => {
  return secureCheck(description).then(() => {
    var todos = new AV.Object('Todos');
    todos.set('id', Math.random() * 100000 | 0);
    todos.set('completed', false);
    todos.set('description', description);
    return todos.save().then(function (res: TodoListItem) {
      return res.toJSON();
    });
  })
}

const deleteTodoItem = (id: string) => {
  const todo = AV.Object.createWithoutData('Todos', id);
  todo.set('completed', true);
  return todo.save().then((res: TodoListItem) => res.toJSON());
}
const updateTodoItem = (id: string, description: string) => {
  return secureCheck(description).then(() => {
    const todo = AV.Object.createWithoutData('Todos', id);
    todo.set('description', description);
    return todo.save().then((res: TodoListItem) => res.toJSON());
  })
}

const createTomato = () => {
  const tomatoes = new AV.Object('Tomatoes')
  tomatoes.set('id', Math.random() * 100000 | 0)
  tomatoes.set('aborted', false)
  tomatoes.set('description', '')
  return tomatoes.save().then((res: TomatoItem) => res.toJSON())
}

interface ParamType {
  objectId: string
  description: string
  aborted: boolean
}

const updateTomato = (param: ParamType) => {
  const { objectId, description, aborted } = param
  return secureCheck(description).then(() => {
    const tomato = AV.Object.createWithoutData('Tomatoes', objectId);
    tomato.set('description', description);
    tomato.set('aborted', aborted)
    return tomato.save().then((res: TomatoItem) => res.toJSON());
  })
}

export { getTodoList, createTodoItem, deleteTodoItem, updateTodoItem, createTomato, updateTomato }