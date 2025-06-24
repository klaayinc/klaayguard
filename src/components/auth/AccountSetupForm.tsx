import React, { useEffect, useState } from "react";
import { useAuth } from "../../context/AuthContext";
import { notify } from "../../utils/utils";
import { Location, useLocation, useNavigate } from "react-router-dom";
import { API_BASE_URL } from "../../constants/api";

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

  const [inputValue, setInputValue] = useState("");
  const [showDropdown, setShowDropdown] = useState(false);

  const filteredAccounts = inputValue
    ? accounts.filter((account) =>
        account.attributes.name.toLowerCase().includes(inputValue.toLowerCase())
      )
    : accounts;

  useEffect(() => {
    if (location.state) {
      setOriginLocation(location);
    }
  }, [location]);

  useEffect(() => {
    const fetchAccounts = async () => {
      setLoading(true);
      try {
        const res = await fetch(`${API_BASE_URL}/accounts`, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (!res.ok) throw new Error("Failed to fetch accounts");
        const data = await res.json();
        setAccounts(data.data); // <-- Fix: use data.data
      } catch (err) {
        setAccounts([]);
      } finally {
        setLoading(false);
      }
    };
    fetchAccounts();
  }, [token]);

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
      // navigate("/home");
    } catch (error) {
      notify(new String(error).toString(), "error");
    }
  };

  return (
    <div className="flex flex-col flex-1 items-center px-8">
      <div className="flex flex-col justify-center flex-1 w-full max-w-md mx-auto">
        <form onSubmit={handleSignIn} autoComplete="off">
          <h2 className="text-2xl font-bold mb-6 text-center">
            Select Account
          </h2>
          <div className="mb-6">
            <label className="block mb-2 font-medium">Account</label>
            {loading ? (
              <p>Loading accounts...</p>
            ) : (
              <div className="relative">
                <input
                  type="text"
                  className="border px-3 py-2 rounded w-full"
                  placeholder="Type to search accounts..."
                  value={
                    selected
                      ? accounts.find((a) => a.id === selected)?.attributes
                          .name || inputValue
                      : inputValue
                  }
                  onChange={(e) => {
                    setInputValue(e.target.value);
                    setSelected(undefined);
                    setShowDropdown(true);
                  }}
                  onFocus={() => setShowDropdown(true)}
                  onBlur={() => setTimeout(() => setShowDropdown(false), 100)}
                />
                {showDropdown && filteredAccounts.length > 0 && (
                  <ul className="absolute z-10 left-0 right-0 bg-white border rounded shadow max-h-48 overflow-auto mt-1">
                    {filteredAccounts.map((account) => (
                      <li
                        key={account.id}
                        className="px-3 py-2 hover:bg-blue-100 cursor-pointer"
                        onMouseDown={() => {
                          setSelected(account.id);
                          setInputValue(account.attributes.name);
                          setShowDropdown(false);
                        }}
                      >
                        {account.attributes.name}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
          <button
            className="w-full bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition disabled:opacity-50"
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
