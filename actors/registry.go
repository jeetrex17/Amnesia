package actors

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	RolePatient   = "patient"
	RoleDoctor    = "doctor"
	RoleAuthority = "authority"
)

type Patient struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

type Doctor struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

type Authority struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

type Registry struct {
	Patients    []Patient   `json:"patients"`
	Doctors     []Doctor    `json:"doctors"`
	Authorities []Authority `json:"authorities"`
}

type ActorInfo struct {
	ID     string
	Name   string
	Role   string
	Active bool
}

var (
	patientIDPattern   = regexp.MustCompile(`^P([0-9]+)$`)
	doctorIDPattern    = regexp.MustCompile(`^D([0-9]+)$`)
	authorityIDPattern = regexp.MustCompile(`^A([0-9]+)$`)
)

func NewDemoRegistry() *Registry {
	return &Registry{
		Patients: []Patient{
			{ID: "P001", Name: "Aarav Patel", Active: true},
			{ID: "P002", Name: "Mira Shah", Active: true},
			{ID: "P007", Name: "Riya Desai", Active: true},
		},
		Doctors: []Doctor{
			{ID: "D001", Name: "Dr. Mehta", Active: true},
			{ID: "D002", Name: "Dr. Rao", Active: true},
		},
		Authorities: []Authority{
			{ID: "A001", Name: "Hospital Records Office", Active: true},
		},
	}
}

func ValidateRole(role string) error {
	switch role {
	case RolePatient, RoleDoctor, RoleAuthority:
		return nil
	default:
		return fmt.Errorf("unsupported role: %s", role)
	}
}

func (r *Registry) Validate() error {
	if r == nil {
		return fmt.Errorf("actor registry is nil")
	}

	seen := make(map[string]struct{})

	for _, patient := range r.Patients {
		if err := validateActorID(patient.ID, RolePatient); err != nil {
			return err
		}
		if err := validateActorName(patient.Name, patient.ID); err != nil {
			return err
		}
		if err := ensureUniqueActorID(seen, patient.ID); err != nil {
			return err
		}
	}

	for _, doctor := range r.Doctors {
		if err := validateActorID(doctor.ID, RoleDoctor); err != nil {
			return err
		}
		if err := validateActorName(doctor.Name, doctor.ID); err != nil {
			return err
		}
		if err := ensureUniqueActorID(seen, doctor.ID); err != nil {
			return err
		}
	}

	for _, authority := range r.Authorities {
		if err := validateActorID(authority.ID, RoleAuthority); err != nil {
			return err
		}
		if err := validateActorName(authority.Name, authority.ID); err != nil {
			return err
		}
		if err := ensureUniqueActorID(seen, authority.ID); err != nil {
			return err
		}
	}

	return nil
}

func (r *Registry) ActivateLegacyDefaults() {
	if allPatientsInactive(r.Patients) {
		for i := range r.Patients {
			r.Patients[i].Active = true
		}
	}
	if allDoctorsInactive(r.Doctors) {
		for i := range r.Doctors {
			r.Doctors[i].Active = true
		}
	}
	if allAuthoritiesInactive(r.Authorities) {
		for i := range r.Authorities {
			r.Authorities[i].Active = true
		}
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

func (r *Registry) HasActivePatient(id string) bool {
	for _, patient := range r.Patients {
		if patient.ID == id {
			return patient.Active
		}
	}

	return false
}

func (r *Registry) HasActiveDoctor(id string) bool {
	for _, doctor := range r.Doctors {
		if doctor.ID == id {
			return doctor.Active
		}
	}

	return false
}

func (r *Registry) HasActiveAuthority(id string) bool {
	for _, authority := range r.Authorities {
		if authority.ID == id {
			return authority.Active
		}
	}

	return false
}

func (r *Registry) ActorByID(id string) (ActorInfo, bool) {
	for _, patient := range r.Patients {
		if patient.ID == id {
			return ActorInfo{ID: patient.ID, Name: patient.Name, Role: RolePatient, Active: patient.Active}, true
		}
	}
	for _, doctor := range r.Doctors {
		if doctor.ID == id {
			return ActorInfo{ID: doctor.ID, Name: doctor.Name, Role: RoleDoctor, Active: doctor.Active}, true
		}
	}
	for _, authority := range r.Authorities {
		if authority.ID == id {
			return ActorInfo{ID: authority.ID, Name: authority.Name, Role: RoleAuthority, Active: authority.Active}, true
		}
	}

	return ActorInfo{}, false
}

func (r *Registry) NextActorID(role string) (string, error) {
	if err := ValidateRole(role); err != nil {
		return "", err
	}

	maxID := 0
	switch role {
	case RolePatient:
		for _, patient := range r.Patients {
			n, err := parseRoleID(patient.ID, role)
			if err != nil {
				return "", err
			}
			if n > maxID {
				maxID = n
			}
		}
		return fmt.Sprintf("P%03d", maxID+1), nil
	case RoleDoctor:
		for _, doctor := range r.Doctors {
			n, err := parseRoleID(doctor.ID, role)
			if err != nil {
				return "", err
			}
			if n > maxID {
				maxID = n
			}
		}
		return fmt.Sprintf("D%03d", maxID+1), nil
	case RoleAuthority:
		for _, authority := range r.Authorities {
			n, err := parseRoleID(authority.ID, role)
			if err != nil {
				return "", err
			}
			if n > maxID {
				maxID = n
			}
		}
		return fmt.Sprintf("A%03d", maxID+1), nil
	default:
		return "", fmt.Errorf("unsupported role: %s", role)
	}
}

func (r *Registry) AddActor(role, name string) (ActorInfo, error) {
	if err := ValidateRole(role); err != nil {
		return ActorInfo{}, err
	}
	if err := validateActorName(name, role); err != nil {
		return ActorInfo{}, err
	}

	id, err := r.NextActorID(role)
	if err != nil {
		return ActorInfo{}, err
	}

	info := ActorInfo{
		ID:     id,
		Name:   strings.TrimSpace(name),
		Role:   role,
		Active: true,
	}

	switch role {
	case RolePatient:
		r.Patients = append(r.Patients, Patient{ID: info.ID, Name: info.Name, Active: true})
	case RoleDoctor:
		r.Doctors = append(r.Doctors, Doctor{ID: info.ID, Name: info.Name, Active: true})
	case RoleAuthority:
		r.Authorities = append(r.Authorities, Authority{ID: info.ID, Name: info.Name, Active: true})
	}

	if err := r.Validate(); err != nil {
		return ActorInfo{}, err
	}

	return info, nil
}

func (r *Registry) DeactivateActor(id string) (ActorInfo, error) {
	for i := range r.Patients {
		if r.Patients[i].ID == id {
			if !r.Patients[i].Active {
				return ActorInfo{}, fmt.Errorf("actor already inactive: %s", id)
			}
			r.Patients[i].Active = false
			return ActorInfo{ID: r.Patients[i].ID, Name: r.Patients[i].Name, Role: RolePatient, Active: false}, nil
		}
	}
	for i := range r.Doctors {
		if r.Doctors[i].ID == id {
			if !r.Doctors[i].Active {
				return ActorInfo{}, fmt.Errorf("actor already inactive: %s", id)
			}
			r.Doctors[i].Active = false
			return ActorInfo{ID: r.Doctors[i].ID, Name: r.Doctors[i].Name, Role: RoleDoctor, Active: false}, nil
		}
	}
	for i := range r.Authorities {
		if r.Authorities[i].ID == id {
			if !r.Authorities[i].Active {
				return ActorInfo{}, fmt.Errorf("actor already inactive: %s", id)
			}
			r.Authorities[i].Active = false
			return ActorInfo{ID: r.Authorities[i].ID, Name: r.Authorities[i].Name, Role: RoleAuthority, Active: false}, nil
		}
	}

	return ActorInfo{}, fmt.Errorf("actor not found: %s", id)
}

func validateActorID(id, role string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%s ID is required", role)
	}

	switch role {
	case RolePatient:
		if !patientIDPattern.MatchString(id) {
			return fmt.Errorf("invalid patient ID format: %s", id)
		}
	case RoleDoctor:
		if !doctorIDPattern.MatchString(id) {
			return fmt.Errorf("invalid doctor ID format: %s", id)
		}
	case RoleAuthority:
		if !authorityIDPattern.MatchString(id) {
			return fmt.Errorf("invalid authority ID format: %s", id)
		}
	default:
		return fmt.Errorf("unsupported role: %s", role)
	}

	return nil
}

func validateActorName(name, context string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("name is required for %s", context)
	}

	return nil
}

func ensureUniqueActorID(seen map[string]struct{}, id string) error {
	if _, exists := seen[id]; exists {
		return fmt.Errorf("duplicate actor ID: %s", id)
	}
	seen[id] = struct{}{}
	return nil
}

func parseRoleID(id, role string) (int, error) {
	var pattern *regexp.Regexp
	switch role {
	case RolePatient:
		pattern = patientIDPattern
	case RoleDoctor:
		pattern = doctorIDPattern
	case RoleAuthority:
		pattern = authorityIDPattern
	default:
		return 0, fmt.Errorf("unsupported role: %s", role)
	}

	matches := pattern.FindStringSubmatch(id)
	if len(matches) != 2 {
		return 0, fmt.Errorf("invalid %s ID format: %s", role, id)
	}

	var n int
	if _, err := fmt.Sscanf(matches[1], "%d", &n); err != nil {
		return 0, fmt.Errorf("parse %s ID: %w", role, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("%s ID must be positive: %s", role, id)
	}

	return n, nil
}

func allPatientsInactive(patients []Patient) bool {
	if len(patients) == 0 {
		return false
	}
	for _, patient := range patients {
		if patient.Active {
			return false
		}
	}

	return true
}

func allDoctorsInactive(doctors []Doctor) bool {
	if len(doctors) == 0 {
		return false
	}
	for _, doctor := range doctors {
		if doctor.Active {
			return false
		}
	}

	return true
}

func allAuthoritiesInactive(authorities []Authority) bool {
	if len(authorities) == 0 {
		return false
	}
	for _, authority := range authorities {
		if authority.Active {
			return false
		}
	}

	return true
}
