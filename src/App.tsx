import { BrowserRouter, Routes, Route } from "react-router-dom";
import SignIn from "./pages/AuthPages/SignIn";
import { Home } from "./pages/Dashboard/Home";
import { AuthProvider } from "./context/AuthContext";
import { ToastContainer } from "react-toastify";
import AccountSetup from "./pages/AuthPages/AccountSetup";

export default function App() {
  return (
    <BrowserRouter>
      <ToastContainer />
      <AuthProvider>
        <Routes>
          <Route path="/" element={<SignIn />} />
          <Route path="/home" element={<Home />} />
          <Route path="/signin" element={<SignIn />} />
          <Route path="/account-setup" element={<AccountSetup />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
