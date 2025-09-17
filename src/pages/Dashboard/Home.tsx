import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { MdLogout, MdArrowBack } from "react-icons/md";
import Button from "../../components/ui/button/Button";

export const Home = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { logout } = useAuth();
  const { accountName, accountId } = location.state || {};

  const handleLogout = () => {
    logout();
    navigate("/signin");
  };

  const handleGoBack = () => {
    navigate("/welcome", {
      state: {
        accountName,
        accountId,
      },
    });
  };

  const handleConfigRowClick = (tableName: string) => {
    setSelectedConfig(tableName);
    // Clear previous query result
    setQueryResult(null);
    // Execute query for the selected table
    execute_query([tableName]);
  };

  return (
    <div className="home items-center relative p-6 bg-gray-100 min-h-screen">
      <div className="flex justify-between mb-4">
        <Button onClick={handleGoBack} variant="outline" title="Go Back">
          <MdArrowBack />
        </Button>
        <Button onClick={handleLogout} variant="outline" title="Logout">
          <MdLogout />
        </Button>
      </div>
      <h1 className="text-2xl font-bold text-center text-gray-800 mb-4">
        Welcome to the KlaayGuard
      </h1>
      <p className="text-center text-gray-600 mb-6">You're signed in. Use the menu to navigate.</p>
    </div>
  );
};
