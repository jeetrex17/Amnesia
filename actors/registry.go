package actors

import "fmt"

type Patient struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Doctor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Authority struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Registry struct {
	Patients    []Patient   `json:"patients"`
	Doctors     []Doctor    `json:"doctors"`
	Authorities []Authority `json:"authorities"`
}

func NewDemoRegistry() *Registry {
	return &Registry{
		Patients: []Patient{
			{ID: "P001", Name: "Alice Sharma"},
			{ID: "P002", Name: "Rahul Patel"},
			{ID: "P007", Name: "Ananya Verma"},
		},
		Doctors: []Doctor{
			{ID: "D001", Name: "Dr. Mehta"},
			{ID: "D002", Name: "Dr. Iyer"},
		},
		Authorities: []Authority{
			{ID: "A001", Name: "Hospital Records Office"},
		},
	}
}

func (r *Registry) HasPatient(id string) bool {
	for _, patient := range r.Patients {
		if patient.ID == id {
			return true
		}
	}

	return false
}

func (r *Registry) HasDoctor(id string) bool {
	for _, doctor := range r.Doctors {
		if doctor.ID == id {
			return true
		}
	}

	return false
}

func (r *Registry) HasAuthority(id string) bool {
	for _, authority := range r.Authorities {
		if authority.ID == id {
			return true
		}
	}

	return false
}

func (r *Registry) Validate() error {
	if r == nil {
		return fmt.Errorf("actor registry is nil")
	}

	patientSeen := make(map[string]struct{})
	for _, patient := range r.Patients {
		if patient.ID == "" {
			return fmt.Errorf("patient ID is required")
		}
		if patient.Name == "" {
			return fmt.Errorf("patient name is required for %s", patient.ID)
		}
		if _, exists := patientSeen[patient.ID]; exists {
			return fmt.Errorf("duplicate patient ID: %s", patient.ID)
		}
		patientSeen[patient.ID] = struct{}{}
	}

	doctorSeen := make(map[string]struct{})
	for _, doctor := range r.Doctors {
		if doctor.ID == "" {
			return fmt.Errorf("doctor ID is required")
		}
		if doctor.Name == "" {
			return fmt.Errorf("doctor name is required for %s", doctor.ID)
		}
		if _, exists := doctorSeen[doctor.ID]; exists {
			return fmt.Errorf("duplicate doctor ID: %s", doctor.ID)
		}
		doctorSeen[doctor.ID] = struct{}{}
	}

	authoritySeen := make(map[string]struct{})
	for _, authority := range r.Authorities {
		if authority.ID == "" {
			return fmt.Errorf("authority ID is required")
		}
		if authority.Name == "" {
			return fmt.Errorf("authority name is required for %s", authority.ID)
		}
		if _, exists := authoritySeen[authority.ID]; exists {
			return fmt.Errorf("duplicate authority ID: %s", authority.ID)
		}
		authoritySeen[authority.ID] = struct{}{}
	}

	return nil
}
