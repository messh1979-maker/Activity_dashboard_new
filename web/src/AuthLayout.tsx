import React from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from '../security/authProvider'
import { useNavigate } from 'react-router-dom'

/** Authentication layout - shows login/register pages */
export const AuthLayout: React.FC = () => {
  const { isLoading, login, init } = useAuth()
  const navigate = useNavigate()
  
  useEffect(() => {
    init()
  }, [init])
  
  if (isLoading) {
    return (
      <div className="rtl min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900">
        <div className="text-center">
          <div className="spinner spinner-sm" />
          <p className="mt-4 text-gray-600 dark:text-gray-300">
            ورود در حال انجام است...
          </p>
        </div>
      </div>
    )
  }
  
  // If already authenticated, redirect to dashboard
  if (!isLoading) {
    const user = localStorage.getItem('user') 
      ? JSON.parse(localStorage.getItem('user') as string)
      : null
    
    if (user) {
      return <Navigate to="/dashboard" replace /> 
    }
  }
  
  return (
    <div className="rtl min-h-screen bg-gray-100 dark:bg-gray-900">
      <div className="max-w-md mx-auto p-6">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6">
          ورود به سامانه
        </h2>
        
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/mfa-challenge" element={<MfaChallengePage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/" element={<Navigate to="/login" replace />} />
        </Routes>
      </div>
    </div>
  )
}

/** Login page */
const LoginPage: React.FC = () => {
  const [credentials, setCredentials] = React.useState({
    identifier: '',
    password: '',
    rememberMe: false
  })
  const [error, setError] = React.useState<string | null>(null)
  const { login } = useAuth()
  const navigate = useNavigate()
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    
    try {
      await login(credentials as any)
      navigate('/dashboard')
    } catch (err: any) {
      setError(err.message || 'ورود ناموفق')
    }
  }
  
  return (
    <div className="space-y-4">
      <form onSubmit={handleSubmit} className="space-y-2">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            شماره ملی / نام کاربری
          </label>
          <input
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            type="text"
            placeholder="0012345678 یا نام کاربری"
            required
            {...credentials.identifier ? {} : 'autoFocus'}
            onChange={(e) => 
              setCredentials({ ...credentials, identifier: e.target.value })}
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            رمز عبور
          </label>
          <input
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            type="password"
            required
            placeholder="••••••••"
            {...credentials.password ? {} : ''}
            onChange={(e) => 
              setCredentials({ ...credentials, password: e.target.value })}
          />
        </div>
        
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={credentials.rememberMe}
              onChange={(e) => 
                setCredentials({ ...credentials, rememberMe: e.target.checked })}
              className="rounded border-gray-300 w-4 h-4 dark:border-gray-600"
            />
            <span className="text-sm text-gray-600 dark:text-gray-300">
              مرا به خاطر بسپار
            </span>
          </div>
          
          <button
            type="submit"
            className="px-4 py-2 rounded-md bg-gray-900 text-white font-medium hover:bg-gray-800 dark:hover:bg-gray-600 transition-colors"
          >
            ورود
          </button>
        </div>
      </form>
      
      {error && (
        <div className="bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded px-3 py-2 text-sm mt-4">
          {error}
        </div>
      )}
      
      <p className="text-center text-sm text-gray-500 dark:text-gray-400">
        یا با حساب_company وارد شوید
      </p>
    </div>
  )
}

/** MFA challenge page */
const MfaChallengePage: React.FC = () => {
  const [code, setCode] = React.useState('')
  const { verifyMFA } = useAuth()
  const navigate = useNavigate()
  const { mfaMethod } = useAuth()
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    try {
      await verifyMFA(code)
      navigate('/dashboard')
    } catch (err: any) {
      setCode('') // Clear on error
      alert(err.message || 'کد MFA نامعتبر است')
    }
  }
  
  if (!mfaMethod) {
    return <p className="text-center text-gray-600">خطا: مfa چالش باز نیست</p>
  }
  
  return (
    <div className="rtl max-w-md mx-auto p-6">
      <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-6">
        اعتبارسنجی امنیتی
      </h3>
      <p className="text-gray-600 dark:text-gray-300 mb-8">
        برای ادامه ورود، کد MFA خود را وارد کنید.<br />
        {mfaMethod === 'totp' && (
          <p className="text-sm">
            می‌توانید از اپلیکیشن Authenticator (Google Authenticator, Authy و...) استفاده کنید
          </p>
        )}
      </p>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            کد MFA
          </label>
          <input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            type="text"
            maxLength="6"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            placeholder="123456"
            required
          />
        </div>
        
        <button
          type="submit"
          className="w-full py-2 rounded-md bg-primary text-white font-medium hover:bg-secondary dark:hover:bg-primary-transition"
        >
          تأیید کد
        </button>
      </form>
    </div>
  )
}

/** Register page */
const RegisterPage: React.FC = () => {
  const [credentials, setCredentials] = React.useState({
    nationalId: '',
    username: '',
    password: '',
    displayName: ''
  })
  const [error, setError] = React.useState<string | null>(null)
  const { register } = useAuth()
  const navigate = useNavigate()
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    
    try {
      await register(credentials as any)
      navigate('/dashboard')
    } catch (err: any) {
      setError(err.message || 'ثبت‌نام ناموفق')
    }
  }
  
  return (
    <div className="rtl max-w-md mx-auto p-6">
      <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-6">
        ثبت‌نام جدید
      </h3>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            کد ملی
          </label>
          <input
            value={credentials.nationalId}
            onChange={(e) => 
              setCredentials({ ...credentials, nationalId: e.target.value })}
            type="text"
            placeholder="0012345678"
            maxLength="10"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
          <p className="text-xs text-gray-500">
            فرمت: ۱۰ رقم با عدد کنترلی
          </p>
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            نام کاربری
          </label>
          <input
            value={credentials.username}
            onChange={(e) => 
              setCredentials({ ...credentials, username: e.target.value })}
            type="text"
            placeholder="username"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            نام نمایشی
          </label>
          <input
            value={credentials.displayName}
            onChange={(e) => 
              setCredentials({ ...credentials, displayName: e.target.value })}
            type="text"
            placeholder="علی رضایی"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
            رمز عبور
          </label>
          <input
            value={credentials.password}
            onChange={(e) => 
              setCredentials({ ...credentials, password: e.target.value })}
            type="password"
            placeholder="••••••••"
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm dark:bg-gray-700 dark:text-white"
            required
          />
        </div>
        
        <button
          type="submit"
          className="w-full py-2 rounded-md bg-primary text-white font-medium hover:bg-secondary dark:hover:bg-primary-transition"
        >
          ثبت‌نام
        </button>
      </form>
      
      {error && (
        <div className="bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded px-3 py-2 text-sm mt-2">
          {error}
        </div>
      )}
    </div>
  )
}

export default AuthLayout