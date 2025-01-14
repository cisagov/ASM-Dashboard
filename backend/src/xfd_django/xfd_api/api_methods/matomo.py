"""Matomo API."""


# Standard Python Libraries
from datetime import datetime, timezone

# Third-Party Libraries
from django.http import JsonResponse
from fastapi import HTTPException
import pymysql


# def get_matomo_data(request):
#     """Get Matomo data."""

#     connection = pymysql.connect(
#         host="localhost",
#         user="root",
#         password="password",
#         database="matomo",
#     )

#     try:
#         with connection.cursor() as cursor:
#             # Example: Fetch basic visit data
#             cursor.execute("""
#                 SELECT idvisit, idsite, visit_first_action_time, visit_total_actions, visitor_id
#                 FROM matomo_log_visit
#                 LIMIT 10
#             """)
#             results = cursor.fetchall()

#         # Transform results into JSON serializable format
#         data = [
#             {
#                 "idvisit": row[0],
#                 "idsite": row[1],
#                 "visit_first_action_time": row[2],
#                 "visit_total_actions": row[3],
#                 "visitor_id": row[4],
#             }
#             for row in results
#         ]

#         return JsonResponse({"data": data}, safe=False)

#     except Exception as e:
#         return JsonResponse({"error": str(e)}, status=500)

#     finally:
#         connection.close()