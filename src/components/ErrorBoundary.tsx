import {Component, type ErrorInfo, type ReactNode} from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  errorMessage: string;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {hasError: false, errorMessage: ''};

  public static getDerivedStateFromError(error: Error): State {
    return {hasError: true, errorMessage: error.message || 'Unexpected rendering error'};
  }

  public componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('CyberTrace Globe ErrorBoundary:', error, info);
  }

  public render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="flex h-screen w-screen items-center justify-center bg-[#050811] p-6 text-slate-200">
          <div className="max-w-lg border border-red-500/40 bg-[#080E1C] p-6">
            <h1 className="text-base font-semibold text-white">Application Recovery</h1>
            <p className="mt-2 text-xs text-slate-300">
              An unexpected error interrupted this workspace view.
            </p>
            <pre className="mt-3 max-h-40 overflow-auto border border-slate-800 bg-[#050811] p-2.5 font-mono text-[11px] text-red-300">
              {this.state.errorMessage}
            </pre>
            <button
              type="button"
              onClick={() => this.setState({hasError: false, errorMessage: ''})}
              className="mt-4 bg-cyan-500 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-400"
            >
              Reload Workspace
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
