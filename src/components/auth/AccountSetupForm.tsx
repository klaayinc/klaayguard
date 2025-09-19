import React, { useEffect, useState } from "react";
import { useAuth } from "../../context/AuthContext";
import { notify } from "../../utils/utils";
import { Location, useLocation, useNavigate } from "react-router-dom";
const BASE_URL = import.meta.env.VITE_API_BASE_URL as string;
if (!BASE_URL) {
  throw new Error("VITE_API_BASE_URL is required");
}

interface Account {
  id: string;
  type: string;
  attributes: {
    name: string;
  };
}

interface AccountSelectorProps {
  selectedAccountId?: string;
}

export const AccountSetupForm: React.FC<AccountSelectorProps> = ({
  selectedAccountId,
}) => {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string | undefined>(
    selectedAccountId
  );
  const [originLocation, setOriginLocation] = useState<Location | null>(null);

  const { token, authenticateUser } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const { username, password } = originLocation?.state || {};

  useEffect(() => {
    if (location.state) {
      setOriginLocation(location);
    }
  }, [location]);

  useEffect(() => {
    const fetchAccounts = async () => {
      setLoading(true);
      try {
        const res = await fetch(`${BASE_URL}/accounts`, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (!res.ok) throw new Error("Failed to fetch accounts");
        const { data } = await res.json();
        setAccounts(data);
      } catch (err) {
        console.error("Error fetching accounts:", err);
        setAccounts([]);
      } finally {
        setLoading(false);
      }
    };
    fetchAccounts();
  }, [token]);

  const handleAccountSelect = (accountId: string) => {
    setSelected(accountId);
  };

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selected) {
      notify("Please select an account to continue.", "warning");
      return;
    }
    if (!username || !password) {
      notify("Missing username or password.", "error");
      return;
    }
    try {
      await authenticateUser(username, password, selected);
      const selectedAccount = accounts.find((acc) => acc.id === selected);
      navigate("/welcome", {
        state: {
          accountName: selectedAccount?.attributes.name,
          accountId: selected,
        },
      });
    } catch (error) {
      notify(new String(error).toString(), "error");
    }
  };

  const getInitials = (name: string) => name.charAt(0).toUpperCase();

  const GrayText: React.FC<{
    children: React.ReactNode;
    className?: string;
  }> = ({ children, className = "" }) => (
    <p className={`text-sm text-gray-500 dark:text-gray-400 ${className}`}>
      {children}
    </p>
  );

  return (
    <div className="flex flex-col flex-1 items-center px-8">
      <div className="flex flex-col justify-center flex-1 w-full max-w-md mx-auto">
        <form onSubmit={handleSignIn} autoComplete="off">
          <h2 className="text-2xl font-bold mb-6 text-center">
            Select Account
          </h2>
          <GrayText className="text-center mb-1">
            Choose which account you'd like to access
          </GrayText>
          <GrayText className="text-center mb-6">Welcome,</GrayText>

          {loading ? (
            <GrayText>Loading accounts...</GrayText>
          ) : (
            <div className="space-y-4 mb-6">
              {accounts.map((account) => (
                <div
                  key={account.id}
                  className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
                    selected === account.id
                      ? "border-blue-500 bg-blue-50 dark:bg-blue-900/20"
                      : "border-gray-200 hover:border-gray-300 dark:border-gray-600 dark:hover:border-gray-500"
                  }`}
                  onClick={() => handleAccountSelect(account.id)}
                >
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center">
                      <span className="text-white font-semibold text-lg">
                        {getInitials(account.attributes.name)}
                      </span>
                    </div>
                    <div className="flex-1">
                      <h3 className="font-medium text-gray-900 dark:text-white">
                        {account.attributes.name}
                      </h3>
                      <GrayText>Account ID: {account.id}</GrayText>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          <button
            className="w-full bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed dark:bg-blue-600 dark:hover:bg-blue-700"
            disabled={!selected}
            type="submit"
          >
            Continue
          </button>
        </form>
      </div>
    </div>
  );
};
