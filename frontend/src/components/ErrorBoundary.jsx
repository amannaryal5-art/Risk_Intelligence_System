import { Component } from 'react'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error) {
    return { error }
  }

  componentDidCatch(error, info) {
    console.error('[CRIE ErrorBoundary]', error, info)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-[#050913] px-6">
          <div className="panel-elevated max-w-lg p-8 text-center">
            <p className="font-mono text-lg text-red-400">Unhandled Error</p>
            <p className="mt-3 text-sm text-slate-400">{this.state.error.message}</p>
            <button
              type="button"
              className="btn-primary mt-6"
              onClick={() => this.setState({ error: null })}
            >
              Dismiss
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
