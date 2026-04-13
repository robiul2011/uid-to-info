import asyncio
import app
import json

async def main():
    # Test the core lookup engine with the user's specific UID
    test_uid = "7346855801"
    target_region = "BD"
    
    print(f"--- Testing OB53 API for UID: {test_uid} (Region: {target_region}) ---")
    
    # Manually trigger startup to load accounts
    await app.startup()
    
    try:
        # This will use the new rotation logic (Trying BD, then ME, then SG)
        res = await app.GetAccountInformation(test_uid, "7", target_region, "/GetPlayerPersonalShow")
        print("\n[SUCCESS] Data retrieved!")
        
        formatted = app.format_response(res)
        print("\n--- RESULTS ---")
        print(f"Name: {formatted['AccountInfo']['AccountName']}")
        print(f"Region: {formatted['AccountInfo']['AccountRegion']}")
        print(f"Level: {formatted['AccountInfo']['AccountLevel']}")
        print(f"Likes: {formatted['AccountInfo']['AccountLikes']}")
        
    except Exception as e:
        print(f"\n[FAILURE] Final error after all retries: {e}")

if __name__ == '__main__':
    asyncio.run(main())
