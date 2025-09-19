import { BrowserRouter, Routes, Route } from "react-router-dom";
import EarthenwareLogin from "./pages/AuthPages/EarthenwareLogin";
// Home page removed; background collection runs in Rust
import { AuthProvider } from "./context/AuthContext";
import { ToastContainer } from "react-toastify";
import AccountSetup from "./pages/AuthPages/AccountSetup";
import WelcomeScreen from "./pages/AuthPages/WelcomeScreen";

export default function App() {
  return (
    <BrowserRouter>
      <ToastContainer />
      <AuthProvider>
        <Routes>
          <Route path="/" element={<EarthenwareLogin />} />
          {/* Home route removed */}
          <Route path="/signin" element={<EarthenwareLogin />} />
          <Route path="/account-setup" element={<AccountSetup />} />
          <Route path="/welcome" element={<WelcomeScreen />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
