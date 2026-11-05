/** Build-time selection: a failed HTTP request never changes the runtime. */
export const browserMode = import.meta.env.VITE_STAKE_RUNTIME === 'browser';
