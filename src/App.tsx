import { BrowserRouter, Routes, Route } from "react-router-dom";
import SignIn from "./pages/AuthPages/SignIn";
import { Home } from "./pages/Dashboard/Home";
import { AuthProvider } from "./context/AuthContext";
import { ToastContainer } from "react-toastify";
import AccountSetup from "./pages/AuthPages/AccountSetup";
import Setup from "./pages/Setup/Setup";
import DevModeBanner from "./components/common/DevModeBanner";

export default function App() {
  return (
    <BrowserRouter>
  <DevModeBanner />
      <ToastContainer />
      <AuthProvider>
        <Routes>
          <Route path="/" element={<SignIn />} />
          <Route path="/home" element={<Home />} />
          <Route path="/signin" element={<SignIn />} />
          <Route path="/account-setup" element={<AccountSetup />} />
          <Route path="/setup" element={<Setup />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
