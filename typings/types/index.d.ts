/// <reference path="./wx/index.d.ts" />
import { Object } from '../../miniprogram/libs/av-core-min';

interface TodoListItem extends Object {
  id?: string,
  description: string,
  completed: boolean
}

interface TomatoItem extends Object {
  id?: string,
  description: string,
  aborted: boolean
}
