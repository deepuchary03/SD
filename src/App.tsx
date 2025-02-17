import React, { useState, useEffect } from "react";
import { Music, Upload, User, Database } from "lucide-react";
import Login from "./components/Login";
import Register from "./components/Register";
import AdminPanel from "./components/AdminPanel";
import MusicPlayer from "./components/MusicPlayer";

function App() {
  const [token, setToken] = useState(localStorage.getItem("token"));
  const [isAdmin, setIsAdmin] = useState(false);
  const [view, setView] = useState("login");
  const [dbStatus, setDbStatus] = useState<{
    connected: boolean;
    message: string;
  }>({
    connected: false,
    message: "Checking database connection...",
  });

  useEffect(() => {
    const checkDbConnection = async () => {
      try {
        const response = await fetch("https://sd-6ykp.onrender.com/api/health");
        const data = await response.json();
        setDbStatus({
          connected: true,
          message: "Connected to MongoDB Atlas",
        });
      } catch (err) {
        setDbStatus({
          connected: false,
          message: "Database connection failed",
        });
      }
    };

    checkDbConnection();
    const interval = setInterval(checkDbConnection, 30000); // Check every 30 seconds

    return () => clearInterval(interval);
  }, []);

  const handleLogin = (newToken: string, admin: boolean) => {
    setToken(newToken);
    setIsAdmin(admin);
    localStorage.setItem("token", newToken);
  };

  const handleLogout = () => {
    setToken(null);
    setIsAdmin(false);
    localStorage.removeItem("token");
    setView("login");
  };

  const renderDbStatus = () => (
    <div
      className={`fixed bottom-4 right-4 flex items-center space-x-2 px-4 py-2 rounded-full shadow-lg ${
        dbStatus.connected
          ? "bg-green-100 text-green-800"
          : "bg-red-100 text-red-800"
      }`}
    >
      <Database
        className={`w-4 h-4 ${
          dbStatus.connected ? "text-green-600" : "text-red-600"
        }`}
      />
      <span className="text-sm font-medium hidden">{dbStatus.message}</span>
    </div>
  );

  if (!token) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-rose-100 via-pink-100 to-rose-50 flex items-center justify-center p-4">
        <div className="w-full max-w-md">
          {view === "login" ? (
            <>
              <Login onLogin={handleLogin} />
              <button
                onClick={() => setView("register")}
                className="mt-4 text-rose-600 hover:text-rose-800 font-medium block mx-auto"
              >
                Need an account? Register
              </button>
            </>
          ) : (
            <>
              <Register onRegister={handleLogin} />
              <button
                onClick={() => setView("login")}
                className="mt-4 text-rose-600 hover:text-rose-800 font-medium block mx-auto"
              >
                Already have an account? Login
              </button>
            </>
          )}
        </div>
        {renderDbStatus()}
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-rose-50 via-pink-50 to-rose-100">
      <nav className="bg-white/80 backdrop-blur-md shadow-md p-4 sticky top-0 z-50">
        <div className="container mx-auto flex justify-between items-center">
          <div className="flex items-center space-x-2">
            <Music className="w-6 h-6 text-rose-500" />
            <span className="text-xl font-bold bg-gradient-to-r from-rose-600 to-pink-600 text-transparent bg-clip-text">
              Music Player
            </span>
          </div>
          <div className="flex items-center space-x-4">
            {isAdmin && (
              <button
                onClick={() => setView("admin")}
                className="flex items-center space-x-1 text-rose-600 hover:text-rose-800 transition-colors duration-200"
              >
                <Upload className="w-5 h-5" />
                <span>Admin Panel</span>
              </button>
            )}
            <button
              onClick={() => setView("player")}
              className="flex items-center space-x-1 text-rose-600 hover:text-rose-800 transition-colors duration-200"
            >
              <Music className="w-5 h-5" />
              <span>Player</span>
            </button>
            <button
              onClick={handleLogout}
              className="flex items-center space-x-1 text-rose-600 hover:text-rose-800 transition-colors duration-200"
            >
              <User className="w-5 h-5" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </nav>

      <main className="container mx-auto py-8 px-4">
        {view === "admin" && isAdmin ? (
          <AdminPanel token={token} />
        ) : (
          <MusicPlayer token={token} />
        )}
      </main>
      {renderDbStatus()}
    </div>
  );
}

export default App;
