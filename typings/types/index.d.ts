/// <reference path="./wx/index.d.ts" />
import { Object } from '../../miniprogram/libs/av-core-min';
import '../../miniprogram/libs/av-core-min'

interface TodoListItem extends Object {
  id?: string,
  description: string,
  completed: boolean
}
