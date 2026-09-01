import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./state/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import AdminRoute from "./components/AdminRoute";
import Register from "./pages/Register";
import VerifyEmail from "./pages/VerifyEmail";
import Login from "./pages/Login";
import Verify2fa from "./pages/Verify2fa";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import Vault from "./pages/Vault";
import Settings from "./pages/Settings";
import EmergencyVaultPage from "./pages/EmergencyVaultPage";
import SharedEntryPage from "./pages/SharedEntryPage";
import SharedReceivedPage from "./pages/SharedReceivedPage";
import SharedVaultsPage from "./pages/SharedVaultsPage";
import SharedVaultDetailPage from "./pages/SharedVaultDetailPage";
import Admin from "./pages/Admin";
import MobileUpdateBanner from "./components/MobileUpdateBanner";
import DesktopAutoUpdater from "./components/DesktopAutoUpdater";
import "./App.css";

function App() {
  const { isAuthenticated } = useAuth();

  return (
    <>
      <MobileUpdateBanner />
      <DesktopAutoUpdater />
      <Routes>
      <Route path="/" element={<Navigate to={isAuthenticated ? "/vault" : "/login"} replace />} />
      <Route path="/register" element={<Register />} />
      <Route path="/verify-email" element={<VerifyEmail />} />
      <Route path="/login" element={<Login />} />
      <Route path="/verify-2fa" element={<Verify2fa />} />
      <Route path="/forgot-password" element={<ForgotPassword />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route
        path="/vault"
        element={
          <ProtectedRoute>
            <Vault />
          </ProtectedRoute>
        }
      />
      <Route
        path="/settings"
        element={
          <ProtectedRoute>
            <Settings />
          </ProtectedRoute>
        }
      />
      <Route
        path="/emergency/:id"
        element={
          <ProtectedRoute>
            <EmergencyVaultPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/shared/:id"
        element={
          <ProtectedRoute>
            <SharedEntryPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/shared-with-me"
        element={
          <ProtectedRoute>
            <SharedReceivedPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/shared-vaults"
        element={
          <ProtectedRoute>
            <SharedVaultsPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/shared-vaults/:id"
        element={
          <ProtectedRoute>
            <SharedVaultDetailPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/admin"
        element={
          <AdminRoute>
            <Admin />
          </AdminRoute>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
}

export default App;
