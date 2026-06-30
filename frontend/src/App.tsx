import { useQuery } from '@tanstack/react-query'

function App() {
  const health = useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const res = await fetch('/api/v1/health')
      if (!res.ok) throw new Error('Health check failed')
      return res.json()
    },
  })

  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-center">
        <h1 className="text-2xl font-bold">VulnServe</h1>
        <p className="text-muted-foreground mt-2">
          Vulnerability Management Platform
        </p>
        <div className="mt-4">
          {health.isLoading && <p className="text-sm">Connecting to API...</p>}
          {health.isError && (
            <p className="text-sm text-destructive">API unreachable</p>
          )}
          {health.isSuccess && (
            <p className="text-sm text-green-600">API connected</p>
          )}
        </div>
      </div>
    </div>
  )
}

export default App
