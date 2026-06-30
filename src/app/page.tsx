import Link from 'next/link'

export default function HomePage() {
  return (
    <main className="flex min-h-screen items-center justify-center">
      <div className="text-center space-y-4">
        <h1 className="text-3xl font-bold">Welcome</h1>
        <Link
          href="/login"
          className="inline-block rounded-md bg-black px-6 py-2 text-white hover:bg-gray-800 transition-colors"
        >
          Sign in
        </Link>
      </div>
    </main>
  )
}
