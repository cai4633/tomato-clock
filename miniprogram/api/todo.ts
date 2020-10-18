import { TodoListItem } from '../../typings/types/index';
import { http } from './http';

const { AV } = getApp().globalData
const getTodoList = () => {
  return new AV.Query('Todos').descending('createdAt')
    .find()
    .then((todos: TodoListItem[]) => {
      return todos.map((todo) => todo.toJSON())
    })
    .catch(console.error);
}

const createTodoItem = (object: any, description: string) => {
  const todos = new object()
  todos.set('id', Math.random() * 100000 | 0)
  todos.set('completed', false)
  todos.set('description', description)
  return todos.save().then((res: TodoListItem) => res.toJSON())
}

const deleteTodoItem = (id: string) => {
  const todo = AV.Object.createWithoutData('Todos', id);
  todo.set('completed', true);
  return todo.save().then((res: TodoListItem) => res.toJSON());
}
const updateTodoItem = (id: string, description: string) => {
  const todo = AV.Object.createWithoutData('Todos', id);
  todo.set('description', description);
  return todo.save().then((res: TodoListItem) => res.toJSON());
}

const createTomato = () => {
  return http.post('/tomatoes').then((res) => {
    return res && typeof res.data === 'object' ? res.data.resource : []
  })
}

interface ParamType {
  id: number
  description: string
  aborted: boolean
}
const updateTomato = (param: ParamType) => {
  const { id, description, aborted } = param
  return http.put(`/tomatoes/${id}`, {
    description, aborted
  }).then(res => res && typeof res.data === 'object' ? res.data.resource : [])
}
export { getTodoList, createTodoItem, deleteTodoItem, updateTodoItem, createTomato, updateTomato }