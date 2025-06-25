import { GlobalError } from './global.error'

export const NotFoundRecordException = (entity: string = 'record') => GlobalError.NotFound(entity)
