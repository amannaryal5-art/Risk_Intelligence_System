import { create } from 'zustand'

export const useWsStore = create((set) => ({
  feedStatus: null,
  connected: false,
  setFeedStatus: (feedStatus) => set({ feedStatus }),
  setConnected: (connected) => set({ connected }),
}))
