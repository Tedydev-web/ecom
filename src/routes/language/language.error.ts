import { GlobalError } from 'src/shared/global.error'

export const LanguageAlreadyExistsException = GlobalError.UnprocessableEntity('language.error.ALREADY_EXISTS', [
  {
    path: 'id',
  },
])
