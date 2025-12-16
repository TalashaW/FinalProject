# tests/e2e/test_profile_e2e.py
"""
End-to-End Tests for Profile Feature

Tests the complete user workflow from login → profile page → updates → password change
using Playwright for browser automation.

These tests cover:
1. Navigating to profile page
2. Viewing profile information
3. Updating profile fields
4. Changing password
5. Verifying updates persist
"""

import pytest
from uuid import uuid4
from playwright.sync_api import expect


def create_test_user_and_login(page, fastapi_server):
    """
    Helper function to register a user and login.
    Returns the user credentials.
    """
    unique_id = str(uuid4())[:8]
    username = f"testuser_{unique_id}"
    email = f"test_{unique_id}@example.com"
    password = "TestPass123!"
    
    # Register
    page.goto(f"{fastapi_server}register")
    page.fill("#username", username)
    page.fill("#email", email)
    page.fill("#first_name", "Test")
    page.fill("#last_name", "User")
    page.fill("#password", password)
    page.fill("#confirm_password", password)
    page.click("button[type='submit']")
    page.wait_for_url("**/login**", timeout=5000)
    
    # Login
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    page.wait_for_url("**/dashboard", timeout=5000)
    
    return {
        "username": username,
        "email": email,
        "password": password,
        "first_name": "Test",
        "last_name": "User"
    }


# ==============================================================================
# Profile Page Navigation Tests
# ==============================================================================

def test_profile_page_navigation(page, fastapi_server):
    """E2E: Test navigating to profile page from dashboard"""
    user = create_test_user_and_login(page, fastapi_server)
    
    # Navigate to profile page
    page.goto(f"{fastapi_server}profile")
    
    # Verify we're on the profile page
    expect(page.locator("h2:has-text('Profile Information')")).to_be_visible()
    expect(page.locator("h2:has-text('Change Password')")).to_be_visible()


def test_profile_page_requires_auth(page, fastapi_server):
    """E2E: Test profile page redirects to login if not authenticated"""
    # Try to access profile without logging in
    page.goto(f"{fastapi_server}profile")
    
    # Should be redirected to login
    page.wait_for_url("**/login**", timeout=5000)


# ==============================================================================
# View Profile Tests
# ==============================================================================

def test_view_profile_information(page, fastapi_server):
    """E2E: Test viewing profile information displays correctly"""
    user = create_test_user_and_login(page, fastapi_server)
    
    # Navigate to profile
    page.goto(f"{fastapi_server}profile")
    
    # Wait for profile to load
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    # Verify profile fields are populated
    expect(page.locator("#username")).to_have_value(user["username"])
    expect(page.locator("#email")).to_have_value(user["email"])
    expect(page.locator("#first_name")).to_have_value(user["first_name"])
    expect(page.locator("#last_name")).to_have_value(user["last_name"])
    
    # Verify account status shows Active
    expect(page.locator("#accountStatus")).to_contain_text("Active")


# ==============================================================================
# Update Profile Tests
# ==============================================================================

def test_update_profile_all_fields(page, fastapi_server):
    """E2E: Test updating all profile fields successfully"""
    user = create_test_user_and_login(page, fastapi_server)
    
    # Navigate to profile
    page.goto(f"{fastapi_server}profile")
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    # Update all fields
    unique_id = str(uuid4())[:8]
    new_username = f"updated_{unique_id}"
    new_email = f"updated_{unique_id}@example.com"
    
    page.fill("#username", new_username)
    page.fill("#email", new_email)
    page.fill("#first_name", "Updated")
    page.fill("#last_name", "Name")
    
    # Submit form
    page.click("#profileForm button[type='submit']")
    
    # Wait for success message
    page.wait_for_selector("#successAlert:not(.hidden)", timeout=5000)
    expect(page.locator("#successMessage")).to_contain_text("Profile updated successfully")
    
    # Verify fields still show updated values
    expect(page.locator("#username")).to_have_value(new_username)
    expect(page.locator("#email")).to_have_value(new_email)
    expect(page.locator("#first_name")).to_have_value("Updated")
    expect(page.locator("#last_name")).to_have_value("Name")


def test_update_profile_partial(page, fastapi_server):
    """E2E: Test updating only some profile fields"""
    user = create_test_user_and_login(page, fastapi_server)
    
    # Navigate to profile
    page.goto(f"{fastapi_server}profile")
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    # Only update first and last name
    page.fill("#first_name", "PartialUpdate")
    page.fill("#last_name", "NameOnly")
    
    # Submit
    page.click("#profileForm button[type='submit']")
    
    # Wait for success
    page.wait_for_selector("#successAlert:not(.hidden)", timeout=5000)
    
    # Verify updated fields
    expect(page.locator("#first_name")).to_have_value("PartialUpdate")
    expect(page.locator("#last_name")).to_have_value("NameOnly")
    
    # Verify unchanged fields remain the same
    expect(page.locator("#username")).to_have_value(user["username"])
    expect(page.locator("#email")).to_have_value(user["email"])


def test_update_profile_cancel(page, fastapi_server):
    """E2E: Test canceling profile updates reverts changes"""
    user = create_test_user_and_login(page, fastapi_server)
    
    # Navigate to profile
    page.goto(f"{fastapi_server}profile")
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    # Make some changes
    page.fill("#first_name", "TempChange")
    page.fill("#last_name", "TempLast")
    
    # Click cancel
    page.click("#cancelBtn")
    
    # Verify fields reverted to original values
    expect(page.locator("#first_name")).to_have_value(user["first_name"])
    expect(page.locator("#last_name")).to_have_value(user["last_name"])


def test_update_profile_duplicate_username_error(page, fastapi_server):
    """E2E NEGATIVE: Test updating to duplicate username shows error"""
    # Create first user
    user1 = create_test_user_and_login(page, fastapi_server)
    page.goto(f"{fastapi_server}login")
    
    # Create second user
    unique_id = str(uuid4())[:8]
    username2 = f"testuser2_{unique_id}"
    email2 = f"test2_{unique_id}@example.com"
    password2 = "TestPass123!"
    
    page.goto(f"{fastapi_server}register")
    page.fill("#username", username2)
    page.fill("#email", email2)
    page.fill("#first_name", "User")
    page.fill("#last_name", "Two")
    page.fill("#password", password2)
    page.fill("#confirm_password", password2)
    page.click("button[type='submit']")
    page.wait_for_url("**/login**", timeout=5000)
    
    # Login as second user
    page.fill("#username", username2)
    page.fill("#password", password2)
    page.click("button[type='submit']")
    page.wait_for_url("**/dashboard", timeout=5000)
    
    # Go to profile and try to use first user's username
    page.goto(f"{fastapi_server}profile")
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    page.fill("#username", user1["username"])
    page.click("#profileForm button[type='submit']")
    
    # Should show error
    page.wait_for_selector("#errorAlert:not(.hidden)", timeout=5000)
    expect(page.locator("#errorMessage")).to_contain_text("Username already taken")


# ==============================================================================
# Change Password Tests
# ==============================================================================

def test_change_password_success(page, fastapi_server):
    """E2E: Test successfully changing password"""
    user = create_test_user_and_login(page, fastapi_server)
    
    # Navigate to profile
    page.goto(f"{fastapi_server}profile")
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    # Fill in password change form
    new_password = "NewPass456!"
    page.fill("#current_password", user["password"])
    page.fill("#new_password", new_password)
    page.fill("#confirm_new_password", new_password)
    
    # Submit password change
    page.click("#passwordForm button[type='submit']")
    
    # Wait for success
    page.wait_for_selector("#successAlert:not(.hidden)", timeout=5000)
    expect(page.locator("#successMessage")).to_contain_text("Password changed successfully")
    
    # Verify form is reset
    expect(page.locator("#current_password")).to_have_value("")
    expect(page.locator("#new_password")).to_have_value("")
    expect(page.locator("#confirm_new_password")).to_have_value("")
    
    # Logout - SET HANDLER BEFORE CLICKING
    page.on("dialog", lambda dialog: dialog.accept())  # Handler set first
    page.click("#layoutLogoutBtn")
    page.wait_for_url("**/login**", timeout=5000)
    
    # Login with new password
    page.fill("#username", user["username"])
    page.fill("#password", new_password)
    page.click("button[type='submit']")
    
    # Should successfully login
    page.wait_for_url("**/dashboard", timeout=5000)


def test_change_password_wrong_current(page, fastapi_server):
    """E2E NEGATIVE: Test changing password with wrong current password"""
    user = create_test_user_and_login(page, fastapi_server)
    
    # Navigate to profile
    page.goto(f"{fastapi_server}profile")
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    # Fill in password change form with wrong current password
    page.fill("#current_password", "WrongPassword123!")
    page.fill("#new_password", "NewPass456!")
    page.fill("#confirm_new_password", "NewPass456!")
    
    # Submit
    page.click("#passwordForm button[type='submit']")
    
    # Should show error
    page.wait_for_selector("#errorAlert:not(.hidden)", timeout=5000)
    expect(page.locator("#errorMessage")).to_contain_text("Current password is incorrect")


def test_change_password_mismatch(page, fastapi_server):
    """E2E NEGATIVE: Test changing password when new passwords don't match"""
    user = create_test_user_and_login(page, fastapi_server)
    
    # Navigate to profile
    page.goto(f"{fastapi_server}profile")
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    # Fill in password change form with mismatched passwords
    page.fill("#current_password", user["password"])
    page.fill("#new_password", "NewPass456!")
    page.fill("#confirm_new_password", "DifferentPass789!")
    
    # Submit
    page.click("#passwordForm button[type='submit']")
    
    # Should show error
    page.wait_for_selector("#errorAlert:not(.hidden)", timeout=5000)
    expect(page.locator("#errorMessage")).to_contain_text("do not match")


def test_change_password_same_as_current(page, fastapi_server):
    """E2E NEGATIVE: Test changing password to same as current"""
    user = create_test_user_and_login(page, fastapi_server)
    
    # Navigate to profile
    page.goto(f"{fastapi_server}profile")
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    # Try to change to same password
    page.fill("#current_password", user["password"])
    page.fill("#new_password", user["password"])
    page.fill("#confirm_new_password", user["password"])
    
    # Submit
    page.click("#passwordForm button[type='submit']")
    
    # Should show error
    page.wait_for_selector("#errorAlert:not(.hidden)", timeout=5000)
    expect(page.locator("#errorMessage")).to_contain_text("must be different from current password")


def test_change_password_cancel(page, fastapi_server):
    """E2E: Test canceling password change clears form"""
    user = create_test_user_and_login(page, fastapi_server)
    
    # Navigate to profile
    page.goto(f"{fastapi_server}profile")
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    # Fill in some password fields
    page.fill("#current_password", "SomePassword123!")
    page.fill("#new_password", "NewPass456!")
    
    # Click cancel
    page.click("#cancelPasswordBtn")
    
    # Verify form is cleared
    expect(page.locator("#current_password")).to_have_value("")
    expect(page.locator("#new_password")).to_have_value("")
    expect(page.locator("#confirm_new_password")).to_have_value("")


# ==============================================================================
# Complete Workflow Tests
# ==============================================================================

def test_complete_profile_workflow(page, fastapi_server):
    """E2E: Test complete profile management workflow"""
    # Step 1: Register and login
    user = create_test_user_and_login(page, fastapi_server)
    
    # Step 2: Navigate to profile
    page.goto(f"{fastapi_server}profile")
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    # Step 3: Update profile information
    unique_id = str(uuid4())[:8]
    new_username = f"updated_{unique_id}"
    page.fill("#username", new_username)
    page.fill("#first_name", "UpdatedFirst")
    page.click("#profileForm button[type='submit']")
    page.wait_for_selector("#successAlert:not(.hidden)", timeout=5000)
    
    # Step 4: Change password
    new_password = "NewSecurePass123!"
    page.fill("#current_password", user["password"])
    page.fill("#new_password", new_password)
    page.fill("#confirm_new_password", new_password)
    page.click("#passwordForm button[type='submit']")
    page.wait_for_selector("#successAlert:not(.hidden)", timeout=5000)
    
    # Step 5: Logout - SET HANDLER BEFORE CLICKING
    page.on("dialog", lambda dialog: dialog.accept())  #Handler set first
    page.click("#layoutLogoutBtn")
    page.wait_for_url("**/login**", timeout=5000)
    
    # Step 6: Login with updated credentials
    page.fill("#username", new_username)
    page.fill("#password", new_password)
    page.click("button[type='submit']")
    page.wait_for_url("**/dashboard", timeout=5000)
    
    # Step 7: Verify profile changes persisted
    page.goto(f"{fastapi_server}profile")
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    expect(page.locator("#username")).to_have_value(new_username)
    expect(page.locator("#first_name")).to_have_value("UpdatedFirst")


def test_profile_breadcrumb_navigation(page, fastapi_server):
    """E2E: Test breadcrumb navigation on profile page"""
    user = create_test_user_and_login(page, fastapi_server)
    
    # Navigate to profile
    page.goto(f"{fastapi_server}profile")
    page.wait_for_selector("#profileContent:not(.hidden)", timeout=10000)
    
    # Verify breadcrumb exists
    expect(page.locator("nav[aria-label='Breadcrumb']")).to_be_visible()
    
    # Click on Dashboard breadcrumb link
    page.click("nav[aria-label='Breadcrumb'] a:has-text('Dashboard')")
    
    # Should navigate to dashboard
    page.wait_for_url("**/dashboard", timeout=5000)